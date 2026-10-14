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

test('institution and team labels are clearly separated in standings and draw views', async () => {
 const app=await fixture();
 assert.equal(app.run(`getTeamDisplayLabel({institution:'North College',name:'Alpha'})`), 'North College · Alpha');
});

test('regional sections show their section label and purpose in the shared header', async () => {
 const app=loadFrontendDomain();
 await app.run(`getSeedState().then(value => { state = value; session.userEmail = state.appSettings.manager.email; session.view = 'regional-home'; })`);
 const html=app.run('renderRegionalOperationsView()');
 assert.match(html, /<p class="eyebrow">Regional Development<\/p>/);
 assert.match(html, /<h2>Home<\/h2>/);
 assert.match(html, /Regional coordination hub for coordinators and field activity\./);
});

test('tournament tools are grouped and the current section opens its group', async () => {
 const app=loadFrontendDomain();
 await app.run(`getSeedState().then(value => {
   state = value;
   session.userEmail = state.appSettings.manager.email;
   session.view = 'tournaments';
   tournament = createTournamentRecord({name:'Synthetic menu test',format:'No Standard Format'});
   state.tournaments = [tournament];
   session.managedTournamentId = tournament.id;
   session.focusedTournamentSection = 'draw';
 })`);
 const html=app.run('renderMenu()');
 assert.match(html, /Run the event/);
 assert.match(html, /Teams and judges/);
 assert.match(html, /<details class="menu-tools-group" open>/);
 assert.match(html, /<summary>Results<\/summary>/);
});

test('public authentication and registration password fields have accessible visibility controls', async () => {
 const app=await fixture();
 app.run("tournament.status='Open'; tournament.registration={debaterOpen:true}; state.tournaments=[tournament]");
 const authHtml=app.run('renderAuthView()');
 const registrationHtml=app.run('renderPublicRegistrationView("debater")');
 const signupHtml=app.run('renderCreateAccountPublicView()');
 assert.match(authHtml, /data-action="toggle-password-visibility" aria-label="Show password" aria-pressed="false"/);
 assert.match(authHtml, /name="password"[^>]*autocomplete="current-password"/);
 assert.match(registrationHtml, /name="confirmPassword"[^>]*autocomplete="current-password"/);
 assert.match(registrationHtml, /data-action="toggle-password-visibility"/);
 assert.doesNotMatch(authHtml, /name="savePasswordOnDevice" checked/);
 assert.doesNotMatch(signupHtml, /name="savePasswordOnDevice" checked/);
 assert.match(signupHtml, /<label for="password-field-password">Password<\/label>/);
});

test('synthetic account sign-in succeeds and rejects an incorrect password offline', async () => {
 const app=loadFrontendDomain();
 await app.run(`getSeedState().then(async value => {
   state = value;
   window.location.hostname = 'localhost';
   probeCloudBackend = async () => false;
   renderApp = () => {};
   persist = () => {};
   saveState = () => {};
   saveSession = () => {};
   state.users.push(await buildUser('Synthetic Member', 'member@synthetic.test', 'member', 'Synthetic-Passphrase-2026'));
 })`);
 const form = (password) => `({get:key=>({email:'member@synthetic.test',password:${JSON.stringify(password)},savePasswordOnDevice:'off'}[key] ?? null)})`;
 await app.run(`signIn(${form('incorrect')})`);
 assert.equal(app.run('session.userEmail'), '');
 assert.match(app.run('flash.text'), /Incorrect password/);
 await app.run(`signIn(${form('Synthetic-Passphrase-2026')})`);
 assert.equal(app.run('session.userEmail'), 'member@synthetic.test');
});

test('synthetic account creation preserves mismatch errors and signs in a valid new account', async () => {
 const app=loadFrontendDomain();
 await app.run(`getSeedState().then(value => {
   state = value;
   window.location.hostname = 'localhost';
   probeCloudBackend = async () => false;
   renderApp = () => {};
   persist = () => {};
   saveState = () => {};
   saveSession = () => {};
 })`);
 const form = (confirmation) => `({get:key=>({name:'Synthetic Entrant',email:'entrant@synthetic.test',password:'Synthetic-Passphrase-2026',confirmPassword:${JSON.stringify(confirmation)},savePasswordOnDevice:'off'}[key] ?? null)})`;
 await app.run(`signUp(${form('does-not-match')})`);
 assert.match(app.run('flash.text'), /Passwords do not match/);
 assert.equal(app.run('getUserByEmail("entrant@synthetic.test")'), null);
 await app.run(`signUp(${form('Synthetic-Passphrase-2026')})`);
 assert.equal(app.run('session.userEmail'), 'entrant@synthetic.test');
 assert.ok(app.run('getUserByEmail("entrant@synthetic.test")'));
});

test('submitted ballot hides a duplicate official result but keeps a differing result visible', async () => {
 const app=await fixture();
 const htmlFor = (officialRanks) => app.run(`(() => {
     tournament.config.scoringMethod = 'WUDC Team Points';
     const teams = tournament.teams;
     const slots = teams.map((team, index) => ({
       teamId: team.id, entryId: team.id, label: team.name, shortLabel: team.name,
       participantIds: tournament.participants.filter(person => person.teamId === team.id).map(person => person.id),
     }));
     var ballotDraw = createDrawRecord(tournament, {id:'ballot-draw', round:1, room:'Room 1', status:'Published', slots});
     const resultMap = Object.fromEntries(slots.map((slot, index) => [getDrawSlotCheckInKey(slot), {rank: index + 1}]));
     ballotDraw.officialResults = Object.fromEntries(slots.map((slot, index) => [getDrawSlotCheckInKey(slot), {rank: ${JSON.stringify(officialRanks)}[index]}]));
     tournament.draw = [ballotDraw];
     tournament.judges = [createJudgeRecord('Synthetic Chair', 'chair@synthetic.test', '', {panelQuality:'chair'})];
     var ballotAllocation = createJudgeAllocationRecord(tournament, ballotDraw, 'chair@synthetic.test', {id:'ballot-allocation', panelRole:'chair', submittedAt:'2026-10-13T12:00:00Z', ballotResults:resultMap});
     tournament.judgeAllocations = [ballotAllocation];
     return renderJudgeAssignmentCard({tournament, allocation:ballotAllocation, participants:tournament.participants, drawEntry:ballotDraw, judge:tournament.judges[0]});
   })()`);
 assert.equal((htmlFor([1,2]).match(/Official Room Result/g) || []).length, 0);
 assert.equal((htmlFor([2,1]).match(/Official Room Result/g) || []).length, 1);
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
test('draw actions report insufficient entries and publishing reports an unnamed format',async()=>{
 const app=await fixture();
 app.run('tournament.teams=[];tournament.participants=[]');
 assert.equal(app.run('getDrawGenerationReadiness(tournament,1).canGenerate'),false);
 assert.match(app.run('getDrawGenerationReadiness(tournament,1).blocker'),/enough speakers/);
 assert.match(app.run('getRoundReleaseReadiness(tournament,1).warnings.join(" ")'),/format has no name/);
});
test('public registration availability explains the tournament and role switches',async()=>{
 const app=await fixture();
 app.run('tournament.status="closed";tournament.registration.debaterOpen=true;tournament.registration.judgeOpen=false');
 assert.equal(app.run('getTournamentRegistrationAvailability(tournament,"debater").open'),false);
 assert.match(app.run('getTournamentRegistrationAvailability(tournament,"debater").reason'),/Tournament is closed/);
 assert.match(app.run('getTournamentRegistrationAvailability(tournament,"judge").reason'),/Tournament is closed/);
 app.run('tournament.status="open"');
 assert.equal(app.run('getTournamentRegistrationAvailability(tournament,"debater").open'),true);
 assert.match(app.run('getTournamentRegistrationAvailability(tournament,"judge").reason'),/turned off in Setup/);
});
test('audit timestamps use a named month and unambiguous day-first date',async()=>{
 const app=await fixture();
 assert.match(app.run('formatAuditTimestamp("2026-10-12T15:04:00.000Z")'),/^12 Oct 2026,/);
});
test('official team results update standings while underqualified institutions stay off the board',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));var draw=createDrawRecord(tournament,{round:1,room:'Room 1',entries:plan.entries});draw.officialResults=Object.fromEntries(draw.slots.map((slot,index)=>[getDrawSlotCheckInKey(slot),{outcome:index?'loss':'win'}]));tournament.draw=[draw];`);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[0]).wins'),1);
 assert.equal(app.run('getTeamStanding(tournament,tournament.teams[1]).losses'),1);
 assert.equal(app.run('getInstitutionStandings(tournament).length'),0);
});

test('a round cannot publish until its motion is saved',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));
   tournament.rounds=1;
   var room=createDrawRecord(tournament,{id:'motion-room',round:1,room:'Room 1',entries:plan.entries});
   tournament.draw=[room];
   var chair=createJudgeRecord('Chair','chair@test.org','',{panelQuality:'chair'});
   tournament.judges=[chair];
   tournament.judgeAllocations=[createJudgeAllocationRecord(tournament,room,chair.email,{id:'chair-allocation',panelRole:'chair'})];
   tournament.roundControls=buildRoundControls(tournament.rounds,[{round:1,motionTitle:'',motionText:''}]);`);
 assert.equal(app.run('getRoundReleaseReadiness(tournament,1).canPublish'),false);
 assert.match(app.run('getRoundReleaseReadiness(tournament,1).blockers.join(" ")'),/motion before publishing/);
 app.run('tournament.roundControls[0].motionTitle="This House would..."');
 assert.equal(app.run('getRoundReleaseReadiness(tournament,1).canPublish'),true);
});

test('BP team points use speaks as the first tie-break after team points',async()=>{
 const app=await fixture();
 app.run(`tournament=createTournamentRecord({name:'BP Tie Break',format:'British Parliamentary',participantModel:'teams',teamSize:2,teamsPerRoom:4,scoringMethod:'WUDC Team Points'});
   tournament.standings=[
     {id:'beta',teamId:'beta',name:'North Team Beta',points:5,speaks:453,firsts:1},
     {id:'alpha',teamId:'alpha',name:'North Team Alpha',points:5,speaks:451,firsts:1},
     {id:'gamma',teamId:'gamma',name:'North Team Gamma',points:4,speaks:449,firsts:1},
     {id:'delta',teamId:'delta',name:'South Team Delta',points:4,speaks:443,firsts:1},
   ];`);
 assert.deepEqual(JSON.parse(app.run('JSON.stringify(sortStandingsForTournament(tournament.standings,tournament).map(row=>row.name))')),
   ['North Team Beta','North Team Alpha','North Team Gamma','South Team Delta']);
});

test('Use Judge Profile replaces a conflicted chair and clears the saved conflict',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));
   var previousRoom=createDrawRecord(tournament,{id:'previous-chair-room',round:1,room:'Room 1',entries:plan.entries});
   var room=createDrawRecord(tournament,{id:'chair-room',round:2,room:'Room 2',entries:plan.entries});
   tournament.draw=[previousRoom,room];
   tournament.roundControls=buildRoundControls(tournament.rounds,[{round:1,motionTitle:'Previous motion'},{round:2,motionTitle:'Saved motion'}]);
   var conflicted=createJudgeRecord('Conflicted Chair','conflict@test.org','School A',{panelQuality:'chair'});
   var replacement=createJudgeRecord('Replacement Chair','replacement@test.org','',{panelQuality:'chair'});
   tournament.judges=[conflicted,replacement];
   tournament.judgeAllocations=[
     createJudgeAllocationRecord(tournament,previousRoom,conflicted.email,{id:'previous-chair',panelRole:'chair'}),
     createJudgeAllocationRecord(tournament,room,conflicted.email,{id:'old-chair',panelRole:'chair'}),
   ];
   state.tournaments=[tournament];
   updateTournament=(id,updater)=>{state.tournaments=state.tournaments.map(item=>item.id===id?updater(structuredClone(item)):item);tournament=state.tournaments.find(item=>item.id===id)};`);
 assert.equal(app.run('getRoundConflictSummary(tournament,2).severe'),1);
 assert.equal(app.run('JSON.stringify(getDrawEntryConflictReport(tournament,tournament.draw.find(entry=>entry.id==="chair-room")).map(issue=>issue.label).sort())'),'["Judge conflict","Judge repeat exposure","Repeat matchup"]');
 assert.equal(app.run('getRoundReleaseReadiness(tournament,2).canPublish'),false);
 app.run(`assignJudgeAllocation(tournament.id,{get:key=>({drawId:'chair-room',judgeEmail:'replacement@test.org',panelRole:'auto'}[key]||'')})`);
 assert.equal(app.run('tournament.judgeAllocations.length'),2);
 assert.equal(app.run('tournament.judgeAllocations.find(allocation=>allocation.drawId==="chair-room").judgeEmail'),'replacement@test.org');
 assert.equal(app.run('tournament.judgeAllocations.find(allocation=>allocation.drawId==="chair-room").panelRole'),'chair');
 assert.equal(app.run('getRoundConflictSummary(tournament,2).severe'),0);
 assert.equal(app.run('JSON.stringify(getDrawEntryConflictReport(tournament,tournament.draw.find(entry=>entry.id==="chair-room")).map(issue=>issue.label))'),'["Repeat matchup"]');
 assert.equal(app.run('getRoundReleaseReadiness(tournament,2).canPublish'),true);
 await app.run('rehydrateState(state).then(value=>{state=value;tournament=state.tournaments.find(item=>item.id===tournament.id)})');
 assert.equal(app.run('tournament.judgeAllocations.find(allocation=>allocation.drawId==="chair-room").judgeEmail'),'replacement@test.org');
 assert.equal(app.run('getRoundConflictSummary(tournament,2).severe'),0);
});

test('room and judge check-ins are counted and labeled separately',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));
   var room=createDrawRecord(tournament,{id:'checkin-room',round:1,room:'Room 1',entries:plan.entries});
   var slotKey=getDrawSlotCheckInKey(room.slots[0]);room.entryCheckIns={[slotKey]:true};
   var chair=createJudgeRecord('Chair','chair@test.org','',{panelQuality:'chair'});tournament.judges=[chair];
   tournament.draw=[room];tournament.judgeAllocations=[createJudgeAllocationRecord(tournament,room,chair.email,{panelRole:'chair',checkedIn:true})];`);
 const summary=JSON.parse(app.run('JSON.stringify(getRoundStatusSummary(tournament,1))'));
 assert.equal(summary.entryCheckIns,1);
 assert.equal(summary.totalEntryCheckIns,2);
 assert.equal(summary.checkedInJudges,1);
 assert.equal(summary.totalJudges,1);
 const stages=JSON.parse(app.run('JSON.stringify(getRoundTimelineStages(tournament,1,{canManage:true}))'));
 const readiness=stages.find(stage=>stage.label==='Room readiness');
 assert.match(readiness.value,/Competitors 1\/2 • Judges 1\/1 • Ready 0\/1/);
});

test('Round Draw ballot review opens the ballot workflow',async()=>{
 const app=await fixture();
 app.run(`var plan=getDrawGenerationPlan(tournament,getRoundProfileForRound(tournament,1));
   tournament.rounds=1;
   var room=createDrawRecord(tournament,{id:'ballot-room',round:1,room:'Room 1',status:'Published',entries:plan.entries});
   var pending=createDrawRecord(tournament,{id:'pending-room',round:1,room:'Room 2',status:'Published',entries:plan.entries});
   tournament.draw=[room,pending];
   var chair=createJudgeRecord('Chair','chair@test.org','',{panelQuality:'chair'});tournament.judges=[chair];
   tournament.judgeAllocations=[createJudgeAllocationRecord(tournament,room,chair.email,{id:'ballot-chair',panelRole:'chair',submittedAt:'2026-10-13T12:00:00.000Z',ballotResults:{}})];`);
 assert.equal(app.run('getTournamentControlRoomState(tournament).nextSection'),'ballots');
 const html=app.run('getFocusedTournamentSections(tournament).find(section=>section.key==="ballots").render()');
 assert.match(html,/Ballots/);
 assert.match(html,/Reopen ballot/);
 assert.match(html,/Room 1/);
});

test('private BP tournament completes three rounds of submitted ballots and recalculates standings',async()=>{
 const app=await fixture();
 app.run(`tournament=createTournamentRecord({name:'Synthetic Private BP QA',format:'British Parliamentary',participantModel:'teams',teamSize:2,teamsPerRoom:4,rounds:3,scoringMethod:'WUDC Team Points'});
   tournament.publication.dashboardListed=false;tournament.registration.debaterOpen=false;tournament.registration.judgeOpen=false;
   tournament.teams=[];tournament.participants=[];tournament.draw=[];tournament.judgeAllocations=[];
   for (const [name,institution] of [['North Team Beta','Institution Beta'],['North Team Alpha','Institution Alpha'],['North Team Gamma','Institution Gamma'],['South Team Delta','Institution Delta']]) {
     const team=upsertTournamentRegistrationTeam(tournament,name,institution);
     for(let speaker=1;speaker<=2;speaker++) upsertTournamentParticipantRegistration(tournament,{name:name+' Speaker '+speaker,email:name.toLowerCase().replaceAll(' ','')+speaker+'@synthetic.test',institution,team});
   }
   const chair=createJudgeRecord('Synthetic Chair','chair@synthetic.test','',{panelQuality:'chair'});tournament.judges=[chair];
   tournament.roundControls=buildRoundControls(3,[1,2,3].map(round=>({round,motionTitle:'Synthetic motion '+round,motionText:'This House supports synthetic tournament testing.'})));
   state.tournaments=[tournament];
   updateTournament=(id,updater)=>{state.tournaments=state.tournaments.map(item=>item.id===id?updater(structuredClone(item)):item);tournament=state.tournaments.find(item=>item.id===id)};`);
 const drawMarkup=app.run('renderTournamentDrawStudio(tournament)');
 assert.match(drawMarkup,/<input type="checkbox" name="releaseNow" \/>/);
 assert.doesNotMatch(drawMarkup,/<input type="checkbox" name="releaseNow" checked/);
 for(let round=1;round<=3;round++) {
   app.run(`generateTournamentDraw(tournament.id,{get:key=>({round:'${round}',method:'auto',teamsPerRoom:'4',roomPrefix:'QA Room',roomStart:'1'}[key]??null)})`);
   app.run(`tournament.judgeAllocations.push(createJudgeAllocationRecord(tournament,tournament.draw.find(room=>room.round===${round}),'chair@synthetic.test',{id:'synthetic-chair-${round}',panelRole:'chair'}))`);
 }
 assert.equal(app.run('tournament.draw.every(room=>room.status==="Draft")'),true);
 for(let round=1;round<=3;round++) app.run(`releaseDrawRound(tournament.id,'${round}')`);
 assert.equal(app.run('tournament.draw.every(room=>room.status==="Published")'),true);
 app.run("session.userEmail='chair@synthetic.test'");
 for(let round=1;round<=3;round++) {
   const json=app.run(`(()=>{const room=tournament.draw.find(entry=>entry.round===${round});const fields={ballot_action:'submit'};
     room.slots.forEach((slot,index)=>fields[getJudgeRoomResultFieldName(getDrawSlotCheckInKey(slot))]=String(((index+${round}-1)%4)+1));
     room.slots.flatMap(slot=>slot.participantIds).forEach((id,index)=>{
       fields[getJudgeScoreFieldName(id,'Speaker Score')]=String(70+((index+${round})%8));
       (tournament.settings.feedbackCategories||[]).forEach(category=>fields[getJudgeScoreFieldName(id,category)]='70');
       fields[getJudgeNoteFieldName(id)]='Synthetic feedback for round ${round}.';
     });
     return JSON.stringify({roomId:room.id,allocationId:'synthetic-chair-${round}',fields});})()`);
   const payload=JSON.parse(json);
   app.run(`submitJudgeBallot(tournament.id,${JSON.stringify(payload.allocationId)},{get:key=>(${JSON.stringify(payload.fields)})[key]??null})`);
 }
 await app.run('state.tournaments=[tournament]; rehydrateState(state).then(value=>{state=value;tournament=state.tournaments.find(item=>item.name==="Synthetic Private BP QA")})');
 assert.equal(app.run('tournament.draw.length'),3);
 assert.equal(app.run('tournament.draw.every(room=>Object.keys(room.officialResults||{}).length===4)'),true);
 assert.equal(app.run('tournament.judgeAllocations.every(allocation=>Boolean(allocation.submittedAt))'),true);
 assert.equal(app.run('tournament.participants.filter(person=>person.feedback.some(item=>item.note.startsWith("Synthetic feedback"))).length'),8);
 assert.equal(app.run('getComputedStandings(tournament).length'),4);
 assert.equal(app.run('getComputedStandings(tournament).reduce((sum,row)=>sum+row.points,0)'),18);
 assert.equal(app.run('getComputedStandings(tournament).every(row=>row.playedRounds===3)'),true);
 assert.equal(app.run('getSpeakerStandings(tournament).length'),8);
 assert.equal(app.run('getRoundStatusSummary(tournament,3).officialBallots'),1);
 assert.equal(app.run('getRoundControlForRound(tournament,2).motionTitle'),'Synthetic motion 2');
 assert.equal(app.run('tournament.publication.dashboardListed'),false);
 assert.equal(app.run('tournament.registration.debaterOpen || tournament.registration.judgeOpen'),false);
 app.run("session.userEmail='manager@test.org'");
 const ballots=app.run('getFocusedTournamentSections(tournament).find(section=>section.key==="ballots").render()');
 assert.match(ballots,/Speaker marks and feedback/);
 assert.match(ballots,/Synthetic feedback for round/);
});
