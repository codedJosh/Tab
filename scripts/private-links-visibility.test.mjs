import assert from 'node:assert/strict';
import test from 'node:test';
import { loadFrontendDomain } from './helpers/frontend-domain.mjs';

test('account links show only the signed-in account, including for a system admin', async () => {
  const app = loadFrontendDomain();
  await app.run('getSeedState().then(value => { state = value; })');
  app.run(`
    session.userEmail = 'admin@example.org';
    state.users = [
      { email: 'admin@example.org', name: 'Admin', active: true, globalRole: 'system_admin', privateAccessToken: 'admin-token' },
      { email: 'other@example.org', name: 'Other', active: true, globalRole: 'member', privateAccessToken: 'other-token' },
      { email: 'disabled@example.org', name: 'Disabled', active: false, globalRole: 'member', privateAccessToken: 'disabled-token' }
    ];
  `);

  const emails = JSON.parse(
    app.run('JSON.stringify(getUserAccessLinkRecords().map(({ user }) => user.email))'),
  );
  assert.deepEqual(emails, ['admin@example.org']);
});
