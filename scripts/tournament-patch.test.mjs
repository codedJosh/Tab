import test from 'node:test';
import assert from 'node:assert/strict';
import {applyTournamentChanges,tournamentChanges} from '../frontend/tournament-patch.js';
const base={id:'t',participants:[{id:'p1',teamId:'a'},{id:'p2',teamId:'b'}],draw:[]};
test('simultaneous registration and team assignment both survive',()=>{
 const edited=structuredClone(base);edited.participants[0].teamId='c';
 const latest=structuredClone(base);latest.participants.push({id:'p3',teamId:'d'});
 const result=applyTournamentChanges(latest,tournamentChanges(base,edited));
 assert.equal(result.participants.length,3);assert.equal(result.participants[0].teamId,'c');
});
test('two staff can edit different people without a workspace conflict',()=>{
 const one=structuredClone(base);one.participants[0].teamId='c';
 const two=structuredClone(base);two.participants[1].teamId='d';
 const result=applyTournamentChanges(one,tournamentChanges(base,two));
 assert.deepEqual(result.participants.map(p=>p.teamId),['c','d']);
});
test('record reordering preserves a concurrent new registration',()=>{
 const base={teams:[{id:'a',name:'A'},{id:'b',name:'B'}]};
 const reordered={teams:[{id:'b',name:'B'},{id:'a',name:'A'}]};
 const changes=tournamentChanges(base,reordered);
 const latest={teams:[{id:'a',name:'A'},{id:'b',name:'B'},{id:'c',name:'C'}]};
 assert.deepEqual(applyTournamentChanges(latest,changes).teams.map(team=>team.id),['b','a','c']);
});
test('same-field conflict rejects atomically and retry is idempotent',()=>{
 const edited=structuredClone(base);edited.participants[0].teamId='c';const changes=tournamentChanges(base,edited);
 assert.deepEqual(applyTournamentChanges(edited,changes),edited);
 const latest=structuredClone(base);latest.participants[0].teamId='other';
 assert.throws(()=>applyTournamentChanges(latest,changes),/same field/);assert.equal(latest.participants[0].teamId,'other');
});
test('round controls merge edits to different rounds instead of replacing the whole array',()=>{
 const base={roundControls:[{round:1,motionTitle:'Old 1',motionText:'',motionReleased:false},{round:2,motionTitle:'Old 2',motionText:'',motionReleased:false}]};
 const edited=structuredClone(base);edited.roundControls[0].motionTitle='New 1';
 const latest=structuredClone(base);latest.roundControls[1].motionTitle='New 2';
 const result=applyTournamentChanges(latest,tournamentChanges(base,edited));
 assert.deepEqual(result.roundControls.map(control=>control.motionTitle),['New 1','New 2']);
});
test('explicit allocation removal survives a concurrent check-in update to that allocation',()=>{
 const base={judgeAllocations:[{id:'a1',drawId:'d1',checkedIn:false,panelRole:'chair'}]};
 const edited={judgeAllocations:[]};
 const latest={judgeAllocations:[{id:'a1',drawId:'d1',checkedIn:true,panelRole:'chair'}]};
 const result=applyTournamentChanges(latest,tournamentChanges(base,edited));
 assert.deepEqual(result.judgeAllocations,[]);
});
test('malicious object paths cannot change prototypes',()=>{
 assert.throws(()=>applyTournamentChanges(base,[{path:[{key:'__proto__'}],afterExists:true,after:{polluted:true}}]),/Invalid/);
 assert.equal({}.polluted,undefined);
});
