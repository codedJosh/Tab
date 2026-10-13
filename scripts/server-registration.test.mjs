import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync(new URL('../server.mjs',import.meta.url),'utf8');
function fn(name){const start=source.search(new RegExp('(?:async )?function '+name+'\\('));const end=source.slice(start+10).search(/\n(?:async )?function /);return source.slice(start,start+10+end);}
test('registration reads acquire a row lock; ordinary reads do not',async()=>{
 const queries=[];const ctx=vm.createContext({WORKSPACE_ID:'test',ensureWorkspaceState:s=>s,normalizeWorkspaceRevision:Number});
 vm.runInContext(fn('readWorkspaceRecord'),ctx);
 const client={query:async sql=>{queries.push(sql);return {rows:[{state:{},revision:10}]}}};
 await ctx.readWorkspaceRecord(client,{forUpdate:true});await ctx.readWorkspaceRecord(client);
 assert.match(queries[0],/for update$/);assert.doesNotMatch(queries[1],/for update/);
});
test('post-commit email receipts merge into the latest state without deleting concurrent registrations',async()=>{
 const latest={users:[{email:'a@test.org'}],tournaments:[{name:'concurrent registration'}]};
 const ctx=vm.createContext({console,sendPrivateAccessEmail:async({user})=>({email:user.email,status:'sent'}),withTransaction:fn=>fn({}),readWorkspaceRecord:async()=>({state:latest,revision:11}),markPrivateAccessEmailSent:user=>user.sent=true,writeWorkspaceState:async(stateClient,state,options)=>{assert.equal(options.expectedRevision,11);return {state,revision:12}}});
 vm.runInContext(fn('deliverCommittedRegistrationEmails'),ctx);
 const result={state:{users:[{email:'a@test.org'}],tournaments:[]},revision:10,notificationEmails:['a@test.org']};
 await ctx.deliverCommittedRegistrationEmails(result,{},'participant_registration','t');
 assert.equal(result.state.tournaments[0].name,'concurrent registration');assert.equal(result.revision,12);assert.equal(result.state.users[0].sent,true);
});
