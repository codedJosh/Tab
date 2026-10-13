import test from 'node:test';
import assert from 'node:assert/strict';
import {publicWorkspace,privateVisibility,memberWorkspace,applyPrivateEntryCommand} from '../frontend/public-workspace.js';
const workspace={workspaceContractVersion:'test',appSettings:{manager:{email:'admin@example.org',password:'SECRET'},portal:{showFeedbackInPrivatePortal:true,showStandingsInPrivatePortal:true}},users:[{id:'u',email:'private@example.org',active:true,globalRole:'member',passwordHash:'SECRET',privateAccessToken:'ACCOUNT'}],regionalOperations:{banking:'SECRET'},tournaments:[{id:'t',name:'Public',publication:{showFeedbackInPrivatePortal:false,showDrawInPrivatePortal:false,showStandingsInPrivatePortal:true},teams:[{id:'team-a',name:'Team A',institution:'School A'}],participants:[{id:'p',token:'PRIVATE',email:'private@example.org',name:'Debater A',teamId:'team-a',feedback:[{note:'SECRET'}]},{id:'other',token:'OTHER',email:'other@example.org',name:'Debater B'}],draw:[{id:'r1',status:'Published',round:1,room:'Room 1',slots:[{teamId:'team-a',entryId:'team-a',label:'Team A',participantIds:['p']},{teamId:'team-b',entryId:'team-b',label:'Team B',participantIds:['other']}],officialResults:{'team-a':{outcome:'win'},'team-b':{outcome:'loss'}}}]}]};
test('public bootstrap excludes accounts, private tokens, contacts and unreleased feedback',()=>{
 const json=JSON.stringify(publicWorkspace(workspace));
 for(const secret of ['SECRET','ACCOUNT','PRIVATE','OTHER','private@example.org']) assert.equal(json.includes(secret),false);
});
test('a private link is confined to one entry and respects explicit hidden settings',()=>{
 const projected=publicWorkspace(workspace,'PRIVATE');
 assert.equal(projected.tournaments.length,1);
 assert.equal(projected.tournaments[0].participants[0].token,'PRIVATE');
 assert.equal(projected.tournaments[0].participants.length,1);
 assert.equal(projected.tournaments[0].participants[0].feedback.length,0);
 assert.equal(privateVisibility(workspace.tournaments[0],workspace.appSettings,'showFeedbackInPrivatePortal'),false);
 const inherited=structuredClone(workspace);delete inherited.tournaments[0].publication.showFeedbackInPrivatePortal;
 assert.equal(publicWorkspace(inherited,'PRIVATE').tournaments[0].publication.showFeedbackInPrivatePortal,true);
});
test('invalid and ambiguous links fail closed',()=>{
 assert.throws(()=>publicWorkspace(workspace,'missing'),/no longer valid/);
 const duplicate=structuredClone(workspace);duplicate.tournaments[0].participants[1].token='PRIVATE';
 assert.throws(()=>publicWorkspace(duplicate,'PRIVATE'),/no longer valid/);
});
test('hidden draws do not reveal pairings while released standings remain available',()=>{
 const projected=publicWorkspace(workspace,'PRIVATE').tournaments[0];
 assert.deepEqual(projected.draw,[]);
 assert.equal(projected.standings.find(row=>row.teamId==='team-a').wins,1);
 assert.equal(projected.standings.find(row=>row.teamId==='team-b').losses,1);
 assert.equal(projected.participants.some(person=>person.id==='other'),false);
});
test('member view strips bearer credentials and limits private records to the member',()=>{
 const projected=memberWorkspace(workspace,'private@example.org');
 const json=JSON.stringify(projected);
 assert.equal(json.includes('ACCOUNT'),false);
 assert.equal(json.includes('passwordHash'),false);
 assert.deepEqual(projected.users.map(user=>user.email),['private@example.org']);
 assert.equal(projected.tournaments[0].participants.some(person=>person.id==='other'),false);
});
test('regional account links return records only within the assigned region',()=>{
 const regional=structuredClone(workspace);
 regional.users[0].regionalRole='regional_coordinator';
 regional.users[0].regionalRegion='Region 1';
 regional.regionalOperations={reports:[{id:'in',region:'Region 1'},{id:'out',region:'Region 2'}],transportRequests:[{id:'request-in',region:'Region 1'},{id:'request-out',region:'Region 2'}],contacts:[{id:'contact-in',region:'Region 1'},{id:'contact-out',region:'Region 2'}],workshopResources:[{id:'resource'}]};
 const projected=memberWorkspace(regional,'private@example.org');
 assert.deepEqual(projected.regionalOperations.reports.map(row=>row.id),['in']);
 assert.deepEqual(projected.regionalOperations.transportRequests.map(row=>row.id),['request-in']);
 assert.deepEqual(projected.regionalOperations.contacts.map(row=>row.id),['contact-in']);
 assert.deepEqual(projected.regionalOperations.workshopResources.map(row=>row.id),['resource']);
});
test('an elevated account token cannot expose manager data through the member projection',()=>{
 const elevated=structuredClone(workspace);
 elevated.tournaments[0].publication.dashboardListed=false;
 elevated.users.push({id:'admin',email:'admin@example.org',active:true,globalRole:'system_admin',passwordHash:'ADMIN SECRET',privateAccessToken:'ADMIN LINK'});
 const projected=memberWorkspace(elevated,'admin@example.org');
 const json=JSON.stringify(projected);
 assert.equal(json.includes('ADMIN SECRET'),false);
 assert.equal(json.includes('ADMIN LINK'),false);
 assert.equal(projected.users.length,1);
 assert.deepEqual(projected.tournaments,[]);
});
test('debater feedback is limited to the chair assigned to that debater',()=>{
 const feedbackWorkspace=structuredClone(workspace);
 const tournament=feedbackWorkspace.tournaments[0];
 tournament.publication.showFeedbackInPrivatePortal=true;
 tournament.draw[0].participantIds=['p','other'];
 tournament.judgeAllocations=[
  {id:'own-chair',drawId:'r1',judgeEmail:'chair@example.org',panelRole:'Chair',submittedAt:'2026-10-13',participantIds:['p']},
  {id:'other-chair',drawId:'r1',judgeEmail:'other-chair@example.org',panelRole:'chair',submittedAt:'2026-10-13',participantIds:['other']},
 ];
 assert.throws(()=>applyPrivateEntryCommand(feedbackWorkspace,'PRIVATE',{kind:'judge_feedback',allocationId:'other-chair',rating:8,note:'Feedback'}),/unavailable/);
 applyPrivateEntryCommand(feedbackWorkspace,'PRIVATE',{kind:'judge_feedback',allocationId:'own-chair',rating:8,note:'Feedback'});
 assert.equal(tournament.feedbackLedger[0].targetEmail,'chair@example.org');
 assert.equal(tournament.feedbackLedger[0].visibility,'manager_only');
});
test('a generic account link cannot show judge controls without a tournament-scoped link',()=>{
 const judgeWorkspaceData=structuredClone(workspace);
 judgeWorkspaceData.users[0].email='private@example.org';
 judgeWorkspaceData.tournaments[0].judges=[{email:'private@example.org',name:'Judge'}];
 judgeWorkspaceData.tournaments[0].judgeAllocations=[{id:'allocation',drawId:'r1',judgeEmail:'private@example.org',panelRole:'chair'}];
 const accountView=memberWorkspace(judgeWorkspaceData,'private@example.org',{includeJudgeWorkspaces:false});
 assert.deepEqual(accountView.tournaments[0].judges,[]);
 assert.deepEqual(accountView.tournaments[0].judgeAllocations,[]);
 const judgeView=memberWorkspace(judgeWorkspaceData,'private@example.org');
 assert.equal(judgeView.tournaments[0].permissions.judgeEmails[0],'private@example.org');
});
