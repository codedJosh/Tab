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
 assert.equal(app.run('getInstitutionStandings(tournament).length'),0);
});

test('institution standings qualify only with three teams that have results and divide by those teams',async()=>{
 const app=await fixture();
 app.run(`
   const schoolA = tournament.teams[0];
   const schoolB = tournament.teams[1];
   const extraTeams = [
     createTeamRecord('Beta', 'School A'),
     createTeamRecord('Gamma', 'School A'),
     createTeamRecord('Delta', 'School A'),
     createTeamRecord('Beta', 'School B'),
   ];
   tournament.teams = [...tournament.teams, ...extraTeams];
   const results = [
     {wins: 1, losses: 0},
     {wins: 1, losses: 0},
     {wins: 0, losses: 1},
     {wins: 1, losses: 0},
     {wins: 0, losses: 0},
     {wins: 0, losses: 1},
   ];
   tournament.standings = tournament.teams.map((team, index) => ({
     id: 'institution-standing-' + index,
     teamId: team.id,
     name: team.name,
     institution: team.institution,
     ...results[index],
   }));
 `);
 const rows = JSON.parse(app.run('JSON.stringify(getInstitutionStandings(tournament))'));
 assert.equal(rows.length, 1);
 assert.equal(rows[0].institution, 'School A');
 assert.equal(rows[0].teams, 3);
 assert.equal(rows[0].points, 7);
 assert.ok(Math.abs(rows[0].average - 7 / 3) < 0.000001);
});

test('institution participation and points come from completed official team results',async()=>{
 const app=await fixture();
 app.run(`
   const teams = [
     createTeamRecord('A1', 'School A'),
     createTeamRecord('A2', 'School A'),
     createTeamRecord('A3', 'School A'),
     createTeamRecord('A4', 'School A'),
     createTeamRecord('B1', 'School B'),
     createTeamRecord('B2', 'School B'),
     createTeamRecord('B3', 'School B'),
   ];
   tournament.teams = teams;
   tournament.draw = teams.slice(0, 3).map((team, index) => {
     const opponent = teams[index + 4];
     const slots = [team, opponent].map(entry => ({
       type: 'team', entryId: entry.id, teamId: entry.id, teamName: entry.name,
       institution: entry.institution, participantIds: [],
     }));
     const winner = index === 1 ? 1 : 0;
     return {
       id: 'official-result-' + index, round: 1, slots,
       officialResults: Object.fromEntries(slots.map((slot, slotIndex) => [
         slot.entryId, {outcome: slotIndex === winner ? 'win' : 'loss'},
       ])),
     };
   });
 `);
 const rows = JSON.parse(app.run('JSON.stringify(getInstitutionStandings(tournament))'));
 const schoolA = rows.find(row => row.institution === 'School A');
 const schoolB = rows.find(row => row.institution === 'School B');
 assert.equal(schoolA.teams, 3);
 assert.equal(schoolA.wins, 2);
 assert.equal(schoolA.losses, 1);
 assert.equal(schoolA.points, 7);
 assert.ok(Math.abs(schoolA.average - 7 / 3) < 0.000001);
 assert.equal(schoolB.teams, 3);
 assert.equal(schoolB.points, 5);
 assert.equal(schoolB.average, 5 / 3);
});

test('institution standings preserve the tournament scoring profile',async()=>{
 const app=await fixture();
 app.run(`
   tournament = createTournamentRecord({
     name: 'BP Institution Test', format: 'British Parliamentary',
     participantModel: 'teams', teamSize: 2, teamsPerRoom: 4,
     scoringMethod: 'WUDC Team Points',
   });
   const teams = [
     createTeamRecord('A1', 'School A'),
     createTeamRecord('A2', 'School A'),
     createTeamRecord('A3', 'School A'),
     createTeamRecord('A4', 'School A'),
   ];
   tournament.teams = teams;
   tournament.standings = teams.map((team, index) => ({
     id: 'bp-institution-standing-' + index,
     teamId: team.id,
     name: team.name,
     institution: team.institution,
     firsts: index === 0 ? 1 : 0,
     seconds: index === 1 ? 1 : 0,
     thirds: index === 2 ? 1 : 0,
     fourths: index === 3 ? 1 : 0,
   }));
 `);
 const rows = JSON.parse(app.run('JSON.stringify(getInstitutionStandings(tournament))'));
 assert.equal(rows.length, 1);
 assert.equal(rows[0].teams, 4);
 assert.equal(rows[0].points, 6);
 assert.equal(rows[0].average, 1.5);
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
test('official team results update standings while underqualified institutions stay off the board',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));var draw=createDrawRecord(tournament,{round:1,room:'Room 1',entries:plan.entries});draw.officialResults=Object.fromEntries(draw.slots.map((slot,index)=>[getDrawSlotCheckInKey(slot),{outcome:index?'loss':'win'}]));tournament.draw=[draw];`);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[0]).wins'),1);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[1]).losses'),1);
 assert.equal(app.run('getInstitutionStandings(tournament).length'),0);
});
