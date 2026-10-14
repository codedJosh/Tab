import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
function fn(name){const start=source.search(new RegExp('(?:async )?function '+name+'\\('));const end=source.slice(start+10).search(/\n(?:async )?function /);return source.slice(start,start+10+end);}
function actionBlock(action){const start=source.indexOf(`if (action === "${action}")`);const end=source.indexOf('\n    if (action ===',start+1);return source.slice(start,end<0?undefined:end);}
test('registration reads acquire a row lock; ordinary reads do not',async()=>{
 const queries=[];const ctx=vm.createContext({WORKSPACE_ID:'test',ensureWorkspaceState:s=>s,normalizeWorkspaceRevision:Number});
 vm.runInContext(fn('readWorkspaceRecord'),ctx);
 const client={query:async sql=>{queries.push(sql);return {rows:[{state:{},revision:10}]}}};
 await ctx.readWorkspaceRecord(client,{forUpdate:true});await ctx.readWorkspaceRecord(client);
 assert.match(queries[0],/for update$/);assert.doesNotMatch(queries[1],/for update/);
});

test('session validation checks expiry without deleting rows on every request',async()=>{
 const queries=[];
 const ctx=vm.createContext({hashSessionToken:token=>'hash:'+token,WORKSPACE_ID:'test'});
 vm.runInContext(fn('getSession'),ctx);
 const client={query:async(sql,params)=>{queries.push({sql,params});return {rows:[]}}};
 await ctx.getSession(client,'session-token');
 assert.equal(queries.length,1);
 assert.match(queries[0].sql,/expires_at\s*>\s*now\(\)/i);
 assert.deepEqual(Array.from(queries[0].params),['hash:session-token','test']);
});

test('email links ignore attacker-controlled request origins',()=>{
 const ctx=vm.createContext({
  URL,
  PUBLIC_APP_URL:'',
  DEFAULT_PUBLIC_APP_URL:'https://www.jadehummingbird.org',
  normalizePrivateAccessPortal:()=>'',
  normalizePrivateAccessEmailReason:()=>'',
 });
 vm.runInContext([
  fn('resolvePublicDashboardUrl'),
  fn('buildUserAccessUrl'),
  fn('buildPasswordResetUrl'),
 ].join('\n'),ctx);
 const request={headers:{
  origin:'https://attacker.example',
  host:'attacker.example',
  'x-forwarded-host':'attacker.example',
  referer:'https://attacker.example/reset',
 }};
 const privateLink=new URL(ctx.buildUserAccessUrl(request,'private-token'));
 const resetLink=new URL(ctx.buildPasswordResetUrl(request,'reset-token'));
 assert.equal(privateLink.origin,'https://www.jadehummingbird.org');
 assert.equal(privateLink.searchParams.get('access'),'private-token');
 assert.equal(resetLink.origin,'https://www.jadehummingbird.org');
 assert.equal(resetLink.searchParams.get('reset'),'reset-token');
});

test('browser API access accepts JADE and configured app origins only',()=>{
 const ctx=vm.createContext({URL,PUBLIC_APP_URL:'https://staging.jade.example/app'});
 vm.runInContext(fn('isAllowedBrowserOrigin'),ctx);
 assert.equal(ctx.isAllowedBrowserOrigin('https://www.jadehummingbird.org'),true);
 assert.equal(ctx.isAllowedBrowserOrigin('https://staging.jade.example'),true);
 assert.equal(ctx.isAllowedBrowserOrigin('https://attacker.example'),false);
 assert.equal(ctx.isAllowedBrowserOrigin('null'),false);
});

test('allowed preflight responses include Access-Control-Allow-Origin',()=>{
 const ctx=vm.createContext({URL,PUBLIC_APP_URL:''});
 vm.runInContext(`${fn('isAllowedBrowserOrigin')}\n${fn('applyBrowserCorsHeaders')}`,ctx);
 const headers={};
 const response={setHeader:(name,value)=>{headers[name.toLowerCase()]=value}};
 const result=ctx.applyBrowserCorsHeaders({headers:{origin:'https://www.jadehummingbird.org'}},response);
 assert.equal(result.allowed,true);
 assert.equal(headers['access-control-allow-origin'],'https://www.jadehummingbird.org');
 const rejectedHeaders={};
 const rejected=ctx.applyBrowserCorsHeaders({headers:{origin:'https://attacker.example'}},{setHeader:(name,value)=>{rejectedHeaders[name.toLowerCase()]=value}});
 assert.equal(rejected.allowed,false);
 assert.equal(rejectedHeaders['access-control-allow-origin'],undefined);
});

test('new account sessions are scoped unless the account is a system administrator',()=>{
 const ctx=vm.createContext({
  normalizeEmail:value=>String(value||'').trim().toLowerCase(),
  isSystemAdmin:(_state,email)=>email==='admin@example.org',
  memberWorkspace:(_state,email)=>({readOnlyProjection:true,email}),
 });
 vm.runInContext(fn('getAuthenticatedAccountAccess'),ctx);
 const member=ctx.getAuthenticatedAccountAccess({privateTokens:['secret']},' MEMBER@example.org ');
 assert.deepEqual(JSON.parse(JSON.stringify(member)),{
  state:{readOnlyProjection:true,email:'member@example.org'},
  sessionScope:{role:'member',email:'member@example.org'},
 });
 const admin=ctx.getAuthenticatedAccountAccess({privateTokens:['secret']},'admin@example.org');
 assert.equal(admin.sessionScope,null);
 assert.deepEqual(JSON.parse(JSON.stringify(admin.state)),{privateTokens:['secret']});
});

test('public and self-service account routes do not return the full workspace',()=>{
 const signup=actionBlock('sign_up');
 assert.match(signup,/getAuthenticatedAccountAccess\(nextWorkspace\.state, email\)/);
 assert.match(signup,/issueSession\(client, email, accountAccess\.sessionScope\)/);
 const debater=actionBlock('register_debater');
 assert.match(debater,/issueSession\(client, email, accountAccess\.sessionScope\)/);
 assert.match(debater,/result\.state = getAuthenticatedAccountAccess\(result\.state, email\)\.state/);
 const judge=actionBlock('register_judge');
 assert.match(judge,/issueSession\(client, email, accountAccess\.sessionScope\)/);
 assert.match(judge,/result\.state = getAuthenticatedAccountAccess\(result\.state, email\)\.state/);
 for (const action of ['request_password_reset','reset_password_with_token']) {
  assert.doesNotMatch(actionBlock(action),/sendStatePayload\(response/);
 }
 assert.match(actionBlock('send_private_link_email'),/getAuthenticatedAccountAccess\(savedWorkspace\.state, actorEmail\)\.state/);
});

test('post-commit email receipts merge into the latest state without deleting concurrent registrations',async()=>{
 const latest={users:[{email:'a@test.org'}],tournaments:[{name:'concurrent registration'}]};
 const ctx=vm.createContext({console,sendPrivateAccessEmail:async({user})=>({email:user.email,status:'sent'}),withTransaction:fn=>fn({}),readWorkspaceRecord:async()=>({state:latest,revision:11}),markPrivateAccessEmailSent:user=>user.sent=true,writeWorkspaceState:async(stateClient,state,options)=>{assert.equal(options.expectedRevision,11);return {state,revision:12}}});
 vm.runInContext(fn('deliverCommittedRegistrationEmails'),ctx);
 const result={state:{users:[{email:'a@test.org'}],tournaments:[]},revision:10,notificationEmails:['a@test.org']};
 await ctx.deliverCommittedRegistrationEmails(result,{},'participant_registration','t');
 assert.equal(result.state.tournaments[0].name,'concurrent registration');assert.equal(result.revision,12);assert.equal(result.state.users[0].sent,true);
});

test('server blocks publishing a round with no saved motion',()=>{
 const ctx=vm.createContext({normalizeEmail:value=>String(value||'').trim().toLowerCase()});
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Draft'}],roundControls:[],judgeAllocations:[]};
 const after={...before,draw:[{...before.draw[0],status:'Published'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/Save a motion/.test(error.message));
});

test('server blocks publishing a room with a judge assigned in multiple roles',()=>{
 const ctx=vm.createContext({normalizeEmail:value=>String(value||'').trim().toLowerCase()});
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,room:'Room 1',status:'Draft'}],roundControls:[{round:1,motionTitle:'Motion'}],judgeAllocations:[]};
 const after={...before,draw:[{...before.draw[0],status:'Published'}],judgeAllocations:[
  {drawId:'room-1',judgeEmail:'judge@example.org',panelRole:'chair'},
  {drawId:'room-1',judgeEmail:'JUDGE@example.org',panelRole:'panelist'},
 ]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/more than one role/.test(error.message));
});

test('server publication guard allows an already published room and unrelated edits',()=>{
 const ctx=vm.createContext({normalizeEmail:value=>String(value||'').trim().toLowerCase()});
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Published'}],roundControls:[],judgeAllocations:[]};
 const after={...before,name:'Updated title'};
 assert.doesNotThrow(()=>ctx.assertDrawReleaseIntegrity(before,after));
});
