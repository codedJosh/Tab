import assert from 'node:assert/strict';
import test from 'node:test';
import { loadFrontendDomain } from './helpers/frontend-domain.mjs';

async function fixture() {
  const app = loadFrontendDomain();
  await app.run('getSeedState().then(value => { state = value; session.userEmail = "manager@test.org"; })');
  app.run(`var tournament = createTournamentRecord({name:'Test',format:'No Standard Format',participantModel:'hybrid',teamSize:4,teamsPerRoom:2,scoringMethod:'WSDC Team Points',randomTeamsAllowed:true});
    tournament.teams=[]; tournament.participants=[]; tournament.draw=[]; tournament.standings=[];
    for (const institution of ['School A','School B']) {
      const team = upsertTournamentRegistrationTeam(tournament,'Alpha',institution);
      for(let i=0;i<4;i++) upsertTournamentParticipantRegistration(tournament,{name:institution+' speaker '+i,email:institution.replace(' ','')+i+'@test.org',institution,team});
    }`);
  return app;
}

test('registration retains stable teams and institutions through rehydration and draw generation', async () => {
 const app=await fixture();
 const ids=app.run('JSON.stringify(tournament.teams.map(team=>team.id))');
 app.run('state.tournaments=[tournament]');
 await app.run('rehydrateState(state).then(value=>{state=value;tournament=state.tournaments[0]})');
 assert.equal(app.run('JSON.stringify(tournament.teams.map(team=>team.id))'),ids);
 assert.equal(app.run('getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1)).entries.length'),2);
 assert.equal(app.run('getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1)).entries.every(entry=>entry.shortLabel === "Alpha" && entry.roster.length===4)'),true);
});

test('incomplete linked teams cannot be silently reshuffled', async()=>{
 const app=await fixture();
 app.run('tournament.participants.pop()');
 assert.match(app.run('getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1)).error'),/3 of 4/);
 assert.equal(app.run('getSupplementalRoundTeamPlan(tournament,getRoundProfileForRound(tournament,1)).supplementalPairingPlan.entries.length'),0);
});

test('conflicting duplicate team IDs survive normalization and block drawing',async()=>{
 const app=await fixture();
 app.run('tournament.participants.forEach(p=>p.teamId=tournament.teams[0].id);tournament.teams[1].id=tournament.teams[0].id');
 assert.equal(app.run('getTournamentTeams(tournament).length'),2);
 assert.match(app.run('getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1)).error'),/Duplicate team ID/);
});

test('a curated team does not hide a legacy registered team',async()=>{
 const app=await fixture();
 app.run('tournament.teams.pop()');
 assert.equal(app.run('getTournamentTeams(tournament).length'),2);
 assert.equal(app.run('getTournamentTeams(tournament).every(team=>getTeamSpeakers(tournament,team).length===4)'),true);
});

test('public registration cannot move a registered speaker or overwrite a shared email',async()=>{
 const app=await fixture();
 assert.throws(()=>app.run(`upsertTournamentParticipantRegistration(tournament,{name:tournament.participants[0].name,email:tournament.participants[0].email,team:tournament.teams[1]})`),/ambiguous registration/);
 assert.throws(()=>app.run(`upsertTournamentParticipantRegistration(tournament,{name:'Another person',email:tournament.participants[0].email,team:tournament.teams[0]})`),/ambiguous registration/);
 assert.equal(app.run('tournament.participants.length'),8);
});

test('same-name teams resolve standings and institution points by stable identity',async()=>{
 const app=await fixture();
 app.run(`tournament.standings=tournament.teams.map((team,index)=>({id:'s'+index,teamId:team.id,name:team.name,institution:team.institution,wins:index?0:2,losses:index?2:0,points:index?0:6}));`);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[1]).losses'),2);
 assert.equal(app.run('getInstitutionStandings(tournament).find(row=>row.institution==="School A").average'),6);
 assert.equal(app.run('getInstitutionStandings(tournament).find(row=>row.institution==="School B").average'),2);
});

test('explicit draw membership prevents substring matches and deleted ballots stop counting',async()=>{
 const app=await fixture();
 app.run(`tournament.draw=[{id:'d',round:1,status:'Published',participantIds:[tournament.participants[0].id],matchup:tournament.participants[1].name}];`);
 assert.equal(app.run('getParticipantDrawEntries(tournament,tournament.participants[1]).length'),0);
 assert.equal(app.run('isOfficialFeedbackEntry(tournament,{allocationId:"deleted",drawId:"d"})'),false);
 assert.equal(app.run('isOfficialFeedbackEntry(tournament,{drawId:"deleted"})'),false);
 assert.equal(app.run('normalizeStandingRecord(normalizeStandingRecord({speaks:150,scoredRounds:2},tournament),tournament).averageSpeaks'),75);
});
test('legacy linked teams remain team entries even without manual team records',async()=>{
 const app=await fixture();app.run('tournament.teams=[]');
 assert.equal(app.run('getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1)).entries.every(entry=>entry.type==="team" && entry.shortLabel==="Alpha")'),true);
});
test('publishing rejects a draft that mixes speakers from registered teams',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));var draw=createDrawRecord(tournament,{round:1,room:'Room 1',entries:plan.entries});draw.slots[0].teamId='random-team';tournament.draw=[draw];`);
 assert.equal(app.run('getRoundReleaseReadiness(tournament,1).canPublish'),false);
 assert.match(app.run('getRoundReleaseReadiness(tournament,1).blockers.join(" ")'),/splits a registered team/);
});
test('official team results feed the correct institution standings',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));var draw=createDrawRecord(tournament,{round:1,room:'Room 1',entries:plan.entries});draw.officialResults=Object.fromEntries(draw.slots.map((slot,index)=>[getDrawSlotCheckInKey(slot),{outcome:index?'loss':'win'}]));tournament.draw=[draw];`);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[0]).wins'),1);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[1]).losses'),1);
 assert.equal(app.run('getInstitutionStandings(tournament).find(row=>row.institution==="School A").average'),3);
 assert.equal(app.run('getInstitutionStandings(tournament).find(row=>row.institution==="School B").average'),1);
});
