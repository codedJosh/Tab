import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
const start = source.indexOf('function assertScoringPersistAuthorization(');
const end = source.indexOf('\nfunction ', start + 10);
const body = source.slice(start, end);

function verify(previous, next) {
  const context = vm.createContext({
    normalizeEmail: (value) => String(value || '').trim().toLowerCase(),
    isSystemAdmin: () => false,
  });
  vm.runInContext(body, context);
  return context.assertScoringPersistAuthorization(previous, next, 'judge@example.org');
}

function ballotStates({ participantIds = ['speaker-a', 'speaker-b'], secondScore = 75, categoryScore = 75 } = {}) {
  const draw = {
    id: 'draw-1', round: 1,
    slots: [
      { teamId: 'team-a', participantIds: ['speaker-a'] },
      { teamId: 'team-b', participantIds: ['speaker-b'] },
    ],
  };
  const oldAllocation = {
    id: 'allocation-1', drawId: draw.id, round: 1, room: 'Room 1',
    judgeEmail: 'judge@example.org', panelRole: 'chair',
    participantIds, submittedAt: '', status: 'assigned',
  };
  const nextAllocation = {
    ...oldAllocation, submittedAt: '2026-10-14T10:00:00.000Z', status: 'submitted',
    ballotResults: { 'team-a': { rank: 1 }, 'team-b': { rank: 2 } },
  };
  const feedback = (participantId, speakerScore) => ({
    id: `feedback-${participantId}`, allocationId: oldAllocation.id,
    drawId: draw.id, judgeEmail: 'judge@example.org', speakerScore,
    scores: { 'Speaker Score': speakerScore, Content: categoryScore },
  });
  const previous = {
    appSettings: {}, regionalOperations: {}, users: [],
    tournaments: [{
      id: 'tournament-1', ownerEmail: '', code: 'T', status: 'active', format: 'British Parliamentary',
      permissions: {}, config: {}, standings: [], settings: { feedbackCategories: ['Content'] },
      judgeAllocations: [oldAllocation], draw: [draw],
      participants: [
        { id: 'speaker-a', teamId: 'team-a', feedback: [] },
        { id: 'speaker-b', teamId: 'team-b', feedback: [] },
      ],
    }],
  };
  const result = {
    ...draw,
    officialResults: { 'team-a': { rank: 1 }, 'team-b': { rank: 2 } },
  };
  const next = structuredClone(previous);
  next.tournaments[0].judgeAllocations = [nextAllocation];
  next.tournaments[0].participants[0].feedback = [feedback('speaker-a', 76)];
  next.tournaments[0].participants[1].feedback = [feedback('speaker-b', secondScore)];
  next.tournaments[0].draw = [result];
  return { previous, next };
}

test('server accepts a complete ballot for exactly the speakers in the assigned room', () => {
  const { previous, next } = ballotStates();
  assert.doesNotThrow(() => verify(previous, next));
});

test('server rejects an allocation whose speaker list differs from the room slots', () => {
  const { previous, next } = ballotStates({ participantIds: ['speaker-a', 'unassigned-speaker'] });
  assert.throws(() => verify(previous, next), (error) => error.code === 'invalid_ballot' && /speakers do not match/.test(error.message));
});

test('server rejects out-of-range optional marks even when the browser is bypassed', () => {
  const { previous, next } = ballotStates({ categoryScore: 101 });
  assert.throws(() => verify(previous, next), (error) => error.code === 'invalid_ballot' && /score range/.test(error.message));
});
