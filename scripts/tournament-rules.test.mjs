import assert from 'node:assert/strict';
import test from 'node:test';
import {registrationTeamSize,resolveRoundStructure,unassignedParticipants} from '../frontend/tournament-rules.js';
test('stale custom sizes cannot override a standard format in registration',()=>{
 const tournament={format:'World Schools',participantModel:'teams',config:{teamSize:4,roundProfiles:[{round:1,teamSize:4}]}};
 assert.equal(registrationTeamSize(tournament),3);
 assert.equal(resolveRoundStructure(tournament,tournament.config.roundProfiles[0]).teamSize,3);
});
test('custom four-person registration agrees with the draw',()=>{
 const tournament={format:'No Standard Format',participantModel:'hybrid',config:{teamSize:4,teamsPerRoom:2}};
 assert.equal(registrationTeamSize(tournament),4);
 assert.equal(resolveRoundStructure(tournament).teamSize,4);
});
test('round format overrides use their own structure',()=>{
 const tournament={format:'World Schools',participantModel:'teams',config:{teamSize:3,roundProfiles:[{format:'No Standard Format',teamSize:4}]}};
 assert.equal(registrationTeamSize(tournament),4);
 assert.equal(resolveRoundStructure(tournament,tournament.config.roundProfiles[0]).teamSize,4);
});
test('random team creation excludes both ID-linked and legacy name-linked people',()=>{
 const people=[{id:'a',teamId:'team'},{id:'b',teamName:'Legacy team'},{id:'c'}];
 assert.deepEqual(unassignedParticipants({participants:people}),[people[2]]);
});
