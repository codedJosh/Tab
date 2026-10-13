const copy = value => structuredClone(value);
function publishedStandings(tournament) {
  const rows = new Map();
  const published = (tournament.draw || []).filter(draw => draw.status === 'Published');
  const teams = new Map((tournament.teams || []).map(team => [String(team.id || ''), team]));
  for (const draw of published) {
    const slots = Array.isArray(draw.slots) ? draw.slots : [];
    const results = draw.officialResults || {};
    const ranked = slots.map(slot => ({slot, result:results[String(slot.entryId || slot.teamId || slot.label || '')] || {}}));
    const complete = ranked.length > 1 && ranked.every(entry => Number(entry.result.rank) > 0 || ['win','loss','draw'].includes(String(entry.result.outcome || '').toLowerCase()));
    if (!complete) continue;
    for (const {slot,result} of ranked) {
      const teamId = String(slot.teamId || '').trim();
      const key = teamId || String(slot.entryId || slot.label || '').trim();
      if (!key) continue;
      const team = teams.get(teamId);
      const row = rows.get(key) || {id:'computed-standing-'+key,teamId,name:String(team?.name || slot.teamName || slot.shortLabel || slot.label || '').trim(),institution:String(team?.institution || slot.institution || '').trim(),wins:0,losses:0,points:0,speaks:0,firsts:0,seconds:0,thirds:0,fourths:0};
      const outcome = String(result.outcome || '').toLowerCase();
      if (outcome === 'win') { row.wins++; row.points += 3; }
      if (outcome === 'loss') { row.losses++; row.points += 1; }
      const rank = Number(result.rank);
      if (Number.isInteger(rank) && rank > 0) {
        const place = ['firsts','seconds','thirds','fourths'][rank - 1];
        if (place) row[place]++;
        row.points += [3,2,1,0][rank - 1] || 0;
      }
      rows.set(key,row);
    }
  }
  return Array.from(rows.values());
}
export function privateVisibility(tournament, settings, key) {
  return tournament?.publication?.[key] ?? settings?.portal?.[key] ?? false;
}
// Construct a public response; never serialize account records or access tokens.
export function publicWorkspace(workspace, token = '') {
  if (!workspace) return null;
  const matches = token ? (workspace.tournaments || []).flatMap(t => (t.participants || []).filter(p => p.token === token).map(p => ({t,p}))) : [];
  if (token && matches.length !== 1) throw Object.assign(new Error('This private link is no longer valid.'),{statusCode:404,code:'invalid_access_link'});
  const access = matches[0];
  const result = {
    workspaceContractVersion: workspace.workspaceContractVersion, version: workspace.version,
    readOnlyProjection: true,
    appSettings: {portal:copy(workspace.appSettings?.portal || {})}, users: [], recoveryRequests: [], regionalOperations: {},
    tournaments: [],
  };
  delete result.appSettings.manager;
  const tournaments = access ? [access.t] : (workspace.tournaments || []).filter(t => t.publication?.dashboardListed !== false);
  result.tournaments = tournaments.map(t => {
    const privateEntry = access?.t.id === t.id ? access.p : null;
    const visible = key => privateVisibility(t, workspace.appSettings, key);
    const showDraw = Boolean(t.publication?.showPublicDraw || (privateEntry && visible('showDrawInPrivatePortal')));
    const showStandings = Boolean(t.publication?.showPublicStandings || (privateEntry && visible('showStandingsInPrivatePortal')));
    const showFeedback = Boolean(privateEntry && visible('showFeedbackInPrivatePortal'));
    const published = (t.draw || []).filter(d => d.status === 'Published');
    const allowedDraws = new Set(published.map(d => d.id));
    const safe = {
      id:t.id, name:t.name, code:t.code, format:t.format, customFormatName:t.customFormatName,
      participantModel:t.participantModel, rounds:t.rounds, status:t.status, bannerImage:t.bannerImage,
      announcement:t.announcement, config:copy(t.config || {}), publication:{
        dashboardListed:t.publication?.dashboardListed !== false,
        showPublicDraw:Boolean(t.publication?.showPublicDraw),
        showPublicStandings:Boolean(t.publication?.showPublicStandings),
        showStandingsInPrivatePortal:Boolean(visible('showStandingsInPrivatePortal')),
        showDrawInPrivatePortal:Boolean(visible('showDrawInPrivatePortal')),
        showFeedbackInPrivatePortal:Boolean(visible('showFeedbackInPrivatePortal')),
        showInstitutionBoard:Boolean(t.publication?.showInstitutionBoard),
      },
      registration:copy(t.registration || {}),
      permissions:{}, auditLog:[], judges:[], notices:[], feedbackLedger:[],
      teams:(t.teams || []).map(({id,name,institution,publicAlias,source})=>({id,name,institution,publicAlias,source})),
      standings:showStandings ? (publishedStandings(t).length ? publishedStandings(t) : copy(t.standings || [])) : [],
      roundControls:(t.roundControls || []).filter(r=>showDraw).map(r=>({round:r.round,motionReleased:Boolean(r.motionReleased),motion:r.motionReleased ? String(r.motion || '') : ''})),
      draw:(showDraw ? published.map(d=>({...copy(d), officialResults:showStandings ? copy(d.officialResults || {}) : {}, entryCheckIns:privateEntry ? Object.fromEntries((d.slots || []).filter(slot=>slot.participantIds?.includes(privateEntry.id)).map(slot=>{const key=String(slot.entryId || slot.teamId || slot.label || "");return [key,Boolean(d.entryCheckIns?.[key])]})) : {}})) : []),
      judgeAllocations:[], participants:[],
    };
    safe.participants=(t.participants || []).map(p=>{
      const own = privateEntry?.id === p.id;
      const scores = showStandings ? {wins:p.wins,losses:p.losses,points:p.points,speakerScore:p.speakerScore,firsts:p.firsts,seconds:p.seconds,thirds:p.thirds,fourths:p.fourths} : {};
      return {id:p.id,name:p.name,teamId:p.teamId,teamName:p.teamName,institution:p.institution,...scores,
        token:own ? token : '',email:'',sanctions:[],
        feedback:(p.feedback || []).filter(f=>(own && showFeedback) && (!f.drawId || allowedDraws.has(f.drawId))).map(f=>({
          id:f.id,drawId:f.drawId,allocationId:f.allocationId,round:f.round,speakerScore:f.speakerScore,scores:copy(f.scores || {}),note:own && showFeedback ? f.note : '',judgeEmail:'',judgeName:f.judgeName || '',createdAt:f.createdAt,createdAtKey:f.createdAtKey,
        })),
      };
    });
    if(showStandings || showFeedback) safe.judgeAllocations=(t.judgeAllocations || []).filter(a=>a.submittedAt && allowedDraws.has(a.drawId)).map(a=>({
      id:a.id,drawId:a.drawId,round:a.round,room:showDraw ? a.room : '',panelRole:a.panelRole,submittedAt:a.submittedAt,
      participantIds:[],judgeEmail:'',
    }));
    if (privateEntry) {
      const visibleParticipantIds = new Set([privateEntry.id]);
      if (showDraw) for (const draw of published) for (const slot of draw.slots || []) for (const id of slot.participantIds || []) visibleParticipantIds.add(id);
      safe.participants = safe.participants.filter(participant=>visibleParticipantIds.has(participant.id));
    }
    return safe;
  });
  return result;
}

export function applyPrivateEntryCommand(workspace, token, command) {
  const matches = (workspace.tournaments || []).flatMap(t => (t.participants || []).filter(p => token && p.token === token).map(p => ({t,p})));
  const access = matches.length === 1 ? matches[0] : null;
  if (!access) throw Object.assign(new Error('This private link is no longer valid.'), {statusCode:403});
  const {t,p} = access;
  const allocation = (t.judgeAllocations || []).find(a=>a.id === command.allocationId);
  const draw = (t.draw || []).find(d=>d.id === (command.drawId || allocation?.drawId) && d.status === 'Published');
  const slot = draw?.slots?.find(s=>s.participantIds?.includes(p.id));
  if (!slot) throw Object.assign(new Error('This link is not assigned to that published room.'),{statusCode:403});
  if (command.kind === 'check_in') {
    if (!(t.publication?.showPublicDraw || privateVisibility(t,workspace.appSettings,'showDrawInPrivatePortal'))) throw Object.assign(new Error('The draw is not released.'),{statusCode:403});
    const key = String(slot.entryId || slot.teamId || slot.label || '');
    draw.entryCheckIns = {...(draw.entryCheckIns || {}), [key]:Boolean(command.checkedIn)};
  } else if (command.kind === 'judge_feedback') {
    const assigned=allocation?.participantIds?.length ? allocation.participantIds : [...new Set([...(draw?.participantIds || []),...(draw?.slots || []).flatMap(entry=>entry.participantIds || [])])];
    if (!allocation?.submittedAt || String(allocation.panelRole || '').toLowerCase() !== 'chair' || !assigned.includes(p.id) || !privateVisibility(t,workspace.appSettings,'showFeedbackInPrivatePortal')) throw Object.assign(new Error('Feedback is unavailable for this ballot.'),{statusCode:403});
    const rating = Number(command.rating), note = String(command.note || '').trim();
    if (!Number.isInteger(rating) || rating < 1 || rating > 10 || !note || note.length > 10000) throw Object.assign(new Error('Enter a score from 1 to 10 and written feedback.'),{statusCode:422});
    const id = 'private-feedback-' + p.id + '-' + allocation.id;
    const entry = {id,type:'team_to_chair',tournamentId:t.id,drawId:draw.id,allocationId:allocation.id,round:draw.round,room:draw.room,participantId:p.id,participantName:p.name,teamName:p.teamName,institution:p.institution,targetEmail:allocation.judgeEmail,sourceEmail:p.email,sourceName:p.name,rating,note,visibility:'manager_only',createdAt:new Date().toISOString(),createdAtKey:Date.now()};
    t.feedbackLedger = [...(t.feedbackLedger || []).filter(e=>e.id !== id),entry];
  } else throw Object.assign(new Error('Unsupported private action.'),{statusCode:422});
  return workspace;
}

export function judgeWorkspace(workspace, email, tournamentId) {
  const normalizedEmail=String(email || '').trim().toLowerCase();
  const t = (workspace.tournaments || []).find(t=>t.id === tournamentId);
  const user = (workspace.users || []).find(u=>String(u.email || '').trim().toLowerCase() === normalizedEmail && u.active);
  if (!t || !user || !(t.judges || []).some(j=>String(j.email || '').trim().toLowerCase() === normalizedEmail)) throw Object.assign(new Error('This judge is no longer assigned to that tournament.'),{statusCode:403});
  const result = publicWorkspace({...workspace,tournaments:[{...t,publication:{...t.publication,dashboardListed:true}}]});
  const visible = result.tournaments[0];
  const ownAllocations = (t.judgeAllocations || []).filter(a=>String(a.judgeEmail || '').trim().toLowerCase() === normalizedEmail);
  const drawIds = new Set(ownAllocations.map(a=>a.drawId));
  visible.draw = (t.draw || []).filter(d=>d.status === 'Published' && drawIds.has(d.id)).map(copy);
  const publishedIds = new Set(visible.draw.map(d=>d.id));
  visible.judgeAllocations = (t.judgeAllocations || []).filter(a=>publishedIds.has(a.drawId)).map(a=>{
    if(String(a.judgeEmail || '').trim().toLowerCase() === normalizedEmail) return copy(a);
    return {id:a.id,drawId:a.drawId,round:a.round,room:a.room,panelRole:a.panelRole,judgeEmail:a.judgeEmail,participantIds:copy(a.participantIds || []),submittedAt:a.submittedAt,ballotResults:a.submittedAt ? copy(a.ballotResults || {}) : {}};
  });
  visible.participants = visible.participants.map(p=>({...p,feedback:(t.participants.find(person=>person.id===p.id)?.feedback || []).filter(f=>String(f.judgeEmail || '').trim().toLowerCase()===normalizedEmail && publishedIds.has(f.drawId)).map(copy)}));
  visible.judges = (t.judges || []).map(j=>({name:j.name,email:j.email,institution:j.institution,panelQuality:j.panelQuality,qualityTier:j.qualityTier}));
  visible.permissions = {judgeEmails:[normalizedEmail]};
  visible.ownerEmail = '';
  visible.roundControls = (t.roundControls || []).filter(r=>visible.draw.some(d=>Number(d.round)===Number(r.round))).map(copy);
  result.users=[{name:user.name,email:normalizedEmail,active:true,globalRole:'member',preferredLandingView:'tournaments'}];
  result.accessScope = {role:'judge',tournamentId};
  return result;
}

export function memberWorkspace(workspace, email, {includeJudgeWorkspaces = true} = {}) {
  const normalized = String(email || '').trim().toLowerCase();
  const sourceUser = (workspace.users || []).find(user=>String(user.email || '').toLowerCase() === normalized && user.active);
  if (!sourceUser) throw Object.assign(new Error('This account is no longer active.'),{statusCode:403});
  const elevated=sourceUser.globalRole === 'manager' || sourceUser.globalRole === 'system_admin' || normalized === String(workspace.appSettings?.manager?.email || '').toLowerCase();
  const projection = publicWorkspace(workspace);
  const own = {id:sourceUser.id,name:sourceUser.name,email:sourceUser.email,active:true,globalRole:'member',preferredLandingView:sourceUser.preferredLandingView,regionalRole:sourceUser.regionalRole || '',regionalRegion:sourceUser.regionalRegion || '',regionalParish:sourceUser.regionalParish || '',regionalBanking:copy(sourceUser.regionalBanking || {}),registeredTournamentIds:copy(sourceUser.registeredTournamentIds || []),pinnedTournamentIds:copy(sourceUser.pinnedTournamentIds || []),archivedTournamentIds:copy(sourceUser.archivedTournamentIds || []),deletedTournamentIds:copy(sourceUser.deletedTournamentIds || [])};
  projection.users=[own];
  projection.recoveryRequests=(workspace.recoveryRequests || []).filter(r=>String(r.email || '').toLowerCase()===normalized).map(copy);
  if (sourceUser.regionalRole && !elevated) {
    const role=String(sourceUser.regionalRole).trim().toLowerCase();
    const canSeeAllRegions=['membership_experience_specialist','regional_development_manager','deputy_regional_development_manager','tertiary_development_specialist'].includes(role);
    const region=String(sourceUser.regionalRegion || '').trim().toLowerCase();
    const inScope=entry=>canSeeAllRegions || (region && String(entry.region || '').trim().toLowerCase()===region);
    projection.regionalOperations={
      reports:(workspace.regionalOperations?.reports || []).filter(inScope).map(copy),
      transportRequests:(workspace.regionalOperations?.transportRequests || []).filter(inScope).map(copy),
      contacts:(workspace.regionalOperations?.contacts || []).filter(inScope).map(copy),
      workshopResources:(workspace.regionalOperations?.workshopResources || []).map(copy),
    };
  }
  const byId=new Map(projection.tournaments.map(t=>[t.id,t]));
  for (const t of workspace.tournaments || []) {
    if (elevated) continue;
    const staffKeys=['managerEmails','tabManagerEmails','tabDirectorEmails','caTeamEmails','tournamentDirectorEmails','convenorEmails','registrationOfficerEmails','financeOfficerEmails','equityOfficerEmails'];
    const backstage=String(t.ownerEmail || '').toLowerCase()===normalized || staffKeys.some(key=>(t.permissions?.[key] || []).some(value=>String(value).toLowerCase()===normalized));
    if (backstage) { byId.set(t.id,copy(t)); continue; }
    if (includeJudgeWorkspaces && (t.judges || []).some(j=>String(j.email || '').toLowerCase()===normalized)) { byId.set(t.id,judgeWorkspace(workspace,normalized,t.id).tournaments[0]); continue; }
    const participant=(t.participants || []).find(p=>String(p.email || '').toLowerCase()===normalized);
    if (participant) {
      const forced={...t,publication:{...t.publication,dashboardListed:true}};
      byId.set(t.id,publicWorkspace({...workspace,tournaments:[forced]},participant.token).tournaments[0]);
    }
  }
  projection.tournaments=Array.from(byId.values());
  projection.readOnlyProjection=false;
  projection.accountScope='member';
  return projection;
}
