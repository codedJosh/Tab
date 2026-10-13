// Pure tournament rules shared by the browser and registration API.
const STANDARD_STRUCTURES = Object.freeze({
  'British Parliamentary': { teamSize: 2, teamsPerRoom: 4, speakersPerSide: 2 },
  'American Parliamentary': { teamSize: 2, teamsPerRoom: 2, speakersPerSide: 2 },
  'JADE Parliamentary': { teamSize: 3, teamsPerRoom: 2, speakersPerSide: 3 },
  'Iron Person British Parliamentary': { teamSize: 1, teamsPerRoom: 4, speakersPerSide: 1 },
  'World Schools': { teamSize: 3, teamsPerRoom: 2, speakersPerSide: 3 },
});
const count = (value, fallback) => Number.isFinite(Number(value)) && Number(value) > 0
  ? Math.min(8, Math.max(1, Math.round(Number(value)))) : fallback;

export function resolveRoundStructure(tournament, profile = {}, options = {}) {
  const config = tournament?.config || {};
  const format = String(profile?.format || tournament?.format || 'No Standard Format').trim();
  const standard = STANDARD_STRUCTURES[format];
  return {
    format,
    isStandardFormat: Boolean(standard),
    teamSize: standard?.teamSize ?? count(profile?.teamSize, count(config.teamSize, 1)),
    teamsPerRoom: standard?.teamsPerRoom ?? count(
      options.allowRoomOverride ? options.roomSizeOverride : profile?.teamsPerRoom,
      count(profile?.teamsPerRoom, count(config.teamsPerRoom, 2))),
    speakersPerSide: standard?.speakersPerSide ?? count(profile?.speakersPerSide, count(config.speakersPerSide, 1)),
  };
}

export function registrationTeamSize(tournament) {
  if (String(tournament?.participantModel || '').trim().toLowerCase() === 'individuals') return 1;
  return Math.max(resolveRoundStructure(tournament).teamSize,
    ...(tournament?.config?.roundProfiles || []).map(profile => resolveRoundStructure(tournament, profile).teamSize));
}

export function unassignedParticipants(tournament) {
  return (tournament.participants || []).filter(person => !String(person.teamId || '').trim() && !String(person.teamName || '').trim());
}
