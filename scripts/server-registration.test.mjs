import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {evaluateDrawEntryConflicts} from '../frontend/draw-integrity.js';
import {resolveRoundStructure, hasInconsistentRoundTeamSizes, registrationTeamSize} from '../frontend/tournament-rules.js';
const source=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
function fn(name){const start=source.search(new RegExp('(?:async )?function '+name+'\\('));const end=source.slice(start+10).search(/\n(?:async )?function /);return source.slice(start,start+10+end);}
function actionBlock(action){const start=source.indexOf(`if (action === "${action}")`);const end=source.indexOf('\n    if (action ===',start+1);return source.slice(start,end<0?undefined:end);}
function integrityContext(){return vm.createContext({normalizeEmail:value=>String(value||'').trim().toLowerCase(),normalizeTextKey:value=>String(value||'').trim().toLowerCase().replace(/[^a-z0-9]+/g,' ').trim(),evaluateDrawEntryConflicts,resolveRoundStructure,hasInconsistentRoundTeamSizes,registrationTeamSize,normalizeTournamentRegistrationSettings:record=>({debaterOpen:record?.debaterOpen!==false,judgeOpen:record?.judgeOpen!==false})});}
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

test('a tournament-triggered private access email names only that tournament',()=>{
 const ctx=vm.createContext({
  normalizeStringList:(values)=>Array.from(new Set(values.map(value=>String(value||'').trim()).filter(Boolean))),
 });
 vm.runInContext(fn('listRecipientTournamentNames'),ctx);
 const state={tournaments:[{id:'event-a',name:'Event A'},{id:'event-b',name:'Event B'}]};
 const user={registeredTournamentIds:['event-a','event-b']};
 assert.deepEqual(Array.from(ctx.listRecipientTournamentNames(state,user,'event-b')),['Event B']);
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

test('sign-up commits the account before delivering its access email',()=>{
 const signup=actionBlock('sign_up');
 assert.doesNotMatch(signup,/await sendPrivateAccessEmail\(/);
 assert.match(signup,/await deliverCommittedRegistrationEmails\(result, request, "sign_up"/);
 assert.ok(signup.indexOf('await deliverCommittedRegistrationEmails') > signup.indexOf('const result = await withTransaction'));
});

test('password reset tokens are committed before the reset email is sent',()=>{
 const reset=actionBlock('request_password_reset');
 assert.ok(reset.indexOf('await writeWorkspaceState(client, state') < reset.indexOf('await sendPasswordResetEmail'));
 assert.match(reset,/resetTokenHash: tokenHash/);
 assert.match(reset,/resetEmailStatus = notification.status/);
});

test('server blocks publishing a round with no saved motion',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Draft'}],roundControls:[],judgeAllocations:[]};
 const after={...before,draw:[{...before.draw[0],status:'Published'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/Save a motion/.test(error.message));
});

test('server blocks publishing a room with a judge assigned in multiple roles',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,room:'Room 1',status:'Draft',slots:[{teamId:'a',teamName:'Alpha'},{teamId:'b',teamName:'Beta'}]}],roundControls:[{round:1,motionTitle:'Motion'}],judges:[{email:'judge@example.org',name:'Judge'}],judgeAllocations:[]};
 const after={...before,draw:[{...before.draw[0],status:'Published'}],judgeAllocations:[
  {drawId:'room-1',judgeEmail:'judge@example.org',panelRole:'chair'},
  {drawId:'room-1',judgeEmail:'JUDGE@example.org',panelRole:'panelist'},
 ]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&error.ruleCode==='JUDGE_ASSIGNED_TWICE_IN_ROOM'&&/assigned more than once/.test(error.message));
});

test('server publication guard allows an already published room and unrelated edits',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Published'}],roundControls:[],judgeAllocations:[]};
 const after={...before,name:'Updated title'};
 assert.doesNotThrow(()=>ctx.assertDrawReleaseIntegrity(before,after));
});

test('server keeps published rooms locked against stale status changes and deletion',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Published'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,{draw:[{...before.draw[0],status:'Draft'}]}),error=>error.code==='published_round_locked');
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,{draw:[]}),error=>error.code==='published_round_locked');
});

test('server keeps published matchups fixed while allowing routine priority edits',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const room={id:'room-1',round:1,room:'Room 1',status:'Published',priority:1,slots:[{teamId:'alpha'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity({draw:[room]},{draw:[{...room,slots:[{teamId:'beta'}]}]}),error=>error.code==='published_round_locked'&&/assignments cannot be changed/.test(error.message));
 assert.doesNotThrow(()=>ctx.assertDrawReleaseIntegrity({draw:[room]},{draw:[{...room,priority:2}]}));
});

test('server publishes a round as one complete set of rooms',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const before={draw:[{id:'room-1',round:1,status:'Draft'},{id:'room-2',round:1,status:'Draft'}]};
 const after={...before,draw:[{...before.draw[0],status:'Published'},before.draw[1]],roundControls:[{round:1,motionTitle:'Motion'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/every room/.test(error.message));
});

test('server accepts a complete conflict-free multi-room round',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const rooms=[
  {id:'r1',round:1,room:'Room 1',status:'Draft',slots:[{teamId:'a',teamName:'Alpha'},{teamId:'b',teamName:'Beta'}]},
  {id:'r2',round:1,room:'Room 2',status:'Draft',slots:[{teamId:'c',teamName:'Gamma'},{teamId:'d',teamName:'Delta'}]},
 ];
 const before={draw:rooms,roundControls:[{round:1,motionTitle:'Motion'}],judgeAllocations:[
  {id:'c1',drawId:'r1',round:1,judgeEmail:'chair1@example.org',panelRole:'chair'},
  {id:'c2',drawId:'r2',round:1,judgeEmail:'chair2@example.org',panelRole:'chair'},
 ]};
 const after={...before,draw:rooms.map(room=>({...room,status:'Published'}))};
 assert.doesNotThrow(()=>ctx.assertDrawReleaseIntegrity(before,after));
});

test('server blocks a judge assigned to two different rooms in one round',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const rooms=[
  {id:'r1',round:1,room:'Room 1',status:'Draft',slots:[{teamId:'a'},{teamId:'b'}]},
  {id:'r2',round:1,room:'Room 2',status:'Draft',slots:[{teamId:'c'},{teamId:'d'}]},
 ];
 const judgeAllocations=[
  {drawId:'r1',round:1,judgeEmail:'judge@example.org',panelRole:'chair'},
  {drawId:'r2',round:1,judgeEmail:'JUDGE@example.org',panelRole:'chair'},
 ];
 const before={draw:rooms,roundControls:[{round:1,motionTitle:'Motion'}],judgeAllocations};
 const after={...before,draw:rooms.map(room=>({...room,status:'Published'}))};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/Room 1 \(Chair\).*Room 2 \(Chair\)/.test(error.message));
});

test('server publication uses the same judge-institution conflict finding as Draw Review',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const rooms=[{id:'r1',round:1,room:'Room 1',status:'Draft',slots:[
  {teamId:'a',teamName:'Alpha',institution:'North College'},
  {teamId:'b',teamName:'Beta',institution:'South College'},
 ]}];
 const before={draw:rooms,roundControls:[{round:1,motionTitle:'Motion'}],teams:[],participants:[],judges:[{email:'chair@example.org',name:'Chair',institution:'North College'}],judgeAllocations:[
  {drawId:'r1',round:1,judgeEmail:'chair@example.org',panelRole:'chair'},
 ]};
 const after={...before,draw:rooms.map(room=>({...room,status:'Published'}))};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&error.ruleCode==='JUDGE_INSTITUTION_CLASH'&&/North College/.test(error.message));
});

test('server blocks publication when a team slot has an incomplete registered roster',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('assertDrawReleaseIntegrity'),ctx);
 const room={id:'r1',round:1,room:'Room 1',status:'Draft',slots:[
  {teamId:'a',teamName:'Alpha',participantIds:['a1']},
  {teamId:'b',teamName:'Beta',participantIds:['b1','b2']},
 ]};
 const before={
  format:'British Parliamentary',participantModel:'teams',config:{roundProfiles:[{round:1,format:'British Parliamentary'}]},
  draw:[room],roundControls:[{round:1,motionTitle:'Motion'}],teams:[{id:'a',name:'Alpha'},{id:'b',name:'Beta'}],
  participants:[{id:'a1',teamId:'a'},{id:'b1',teamId:'b'},{id:'b2',teamId:'b'}],
  judgeAllocations:[{drawId:'r1',round:1,judgeEmail:'chair@example.org',panelRole:'chair'}],
 };
 const after={...before,draw:[{...room,status:'Published'}]};
 assert.throws(()=>ctx.assertDrawReleaseIntegrity(before,after),error=>error.code==='draw_release_blocked'&&/1 speakers; 2 are required/.test(error.message));
});

test('server blocks registration while round team sizes disagree',()=>{
 const ctx=integrityContext();
 vm.runInContext(fn('getTournamentRegistrationAvailability'),ctx);
 const result=ctx.getTournamentRegistrationAvailability({
  status:'Open',participantModel:'teams',registration:{debaterOpen:true},format:'No Standard Format',
  config:{teamSize:4,roundProfiles:[{round:1,teamSize:4},{round:2,teamSize:2}]},
 },'debater');
 assert.equal(result.open,false);
 assert.match(result.reason,/different team sizes/);
});
