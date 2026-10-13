import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../frontend/app.js", import.meta.url), "utf8");
function sourceFunction(name) {
  const start = source.indexOf(`      async function ${name}(`);
  assert.ok(start >= 0, `${name} exists`);
  const next = source.slice(start + 10).search(/\n      (?:async )?function /);
  return source.slice(start, start + 10 + next);
}

function setup(serverRevision) {
  const requests = [];
  let refreshes = 0;
  const context = vm.createContext({
    URL, window: {location: {href: "http://localhost/"}},
    cloudRuntime: { revision: 10, endpoint: "/api" },
    session: { cloudSessionToken: "test-session" },
    WORKSPACE_CONTRACT_VERSION: "test-contract",
    CLOUD_REQUEST_TIMEOUT_MS: 1000,
    CLOUD_FUNCTION_ENDPOINTS: ["/api"],
    LIVE_SYNC_MIN_GAP_MS: 0,
    lastLiveSyncAt: 0,
    normalizeWorkspaceRevision: (value) => Number(value) || 0,
    probeCloudBackend: async () => true,
    canRunLiveSharedRefresh: () => true,
    saveSession: () => {},
    fetchWithTimeout: async (_url, options) => {
      requests.push(JSON.parse(options.body).action);
      return { ok: true, json: async () => ({ revision: serverRevision, contractVersion: "test-contract" }) };
    },
    refreshSharedStateSafely: async () => { refreshes += 1; return true; },
  });
  vm.runInContext(["callCloud", "getCloudWorkspaceRevision", "refreshSharedStateIfIdle"].map(sourceFunction).join("\n"), context);
  return { context, requests, refreshCount: () => refreshes };
}

test("a newly saved registration triggers a shared state refresh", async () => {
  const fixture = setup(11);
  assert.equal(await fixture.context.refreshSharedStateIfIdle(), true);
  assert.equal(fixture.refreshCount(), 1);
  assert.equal(fixture.context.cloudRuntime.revision, 10);
  assert.deepEqual(fixture.requests, ["get_revision"]);
});

test("an unchanged workspace skips the state download", async () => {
  const fixture = setup(10);
  assert.equal(await fixture.context.refreshSharedStateIfIdle(), false);
  assert.equal(fixture.refreshCount(), 0);
});

test("revision checks leave the loaded revision intact; state downloads advance it", async () => {
  const fixture = setup(11);
  assert.equal(await fixture.context.getCloudWorkspaceRevision(), 11);
  assert.equal(fixture.context.cloudRuntime.revision, 10);
  await fixture.context.callCloud("get_state");
  assert.equal(fixture.context.cloudRuntime.revision, 11);
});
