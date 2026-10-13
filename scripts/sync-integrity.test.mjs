import assert from 'node:assert/strict';
import test from 'node:test';
import {loadFrontendDomain} from './helpers/frontend-domain.mjs';

async function fixture(){
 const app=loadFrontendDomain();
 await app.run('getSeedState().then(value=>{state=value;session.userEmail="manager@test.org";session.cloudSessionToken="session";cloudRuntime.revision=10;})');
 app.run(`state.tournaments=[createTournamentRecord({name:"Test",format:"World Schools"})];var stored = new Map(); localStorageGet=key=>stored.get(key)||null;localStorageSet=(key,value)=>{stored.set(key,value);return true};localStorageRemove=key=>stored.delete(key);renderApp=()=>{};saveSession=()=>{};probeCloudBackend=async()=>true;getCurrentUser=()=>({email:session.userEmail});waitForCloudRetry=async()=>{};`);
 return app;
}
test('stale autosave keeps recovery copy and cannot replay over a new registration',async()=>{
 const app=await fixture();
 app.run(`var serverState=clone(state);serverState.tournaments[0].name='New registration from another device';var writes=[];
 callCloud=async(action,payload)=>{if(action==='persist'){writes.push(payload.expectedRevision);throw Object.assign(new Error('stale'),{code:'stale_revision'})}return {state:serverState,revision:11}};
 refreshStateFromBackend=async()=>{state=clone(serverState);cloudRuntime.revision=11;cloudSyncRequiresRefresh=false;return true};`);
 await app.run('queueCloudPersist(); cloudPersistQueue');
 assert.equal(app.run('writes.join(",")'),'10');
 assert.equal(app.run('state.tournaments[0].name'),'New registration from another device');
 assert.equal(app.run('hasPendingCloudSyncForCurrentSession()'),false);
 assert.equal(app.run('JSON.parse(stored.get(CLOUD_SYNC_CONFLICTS_STORAGE_KEY)).length'),1);
});
test('offline snapshot without its base revision is preserved instead of replayed',async()=>{
 const app=await fixture();
 app.run('pendingCloudSync={id:"legacy",state:clone(state),userEmail:session.userEmail}');
 assert.equal(await app.run('preparePendingCloudSyncReplay()'),false);
 assert.equal(app.run('pendingCloudSync'),null);
 assert.equal(app.run('JSON.parse(stored.get(CLOUD_SYNC_CONFLICTS_STORAGE_KEY))[0].id'),'legacy');
});
test('queued local continuation uses acknowledged revision and retains both edits',async()=>{
 const app=await fixture();
 app.run(`var writes=[];var release;
 callCloud=async(action,payload)=>{writes.push({revision:payload.expectedRevision,name:payload.state.tournaments[0].name});if(writes.length===1)await new Promise(resolve=>release=resolve);cloudRuntime.revision=payload.expectedRevision+1;return {revision:cloudRuntime.revision}};`);
 app.run('state.tournaments[0].name="first edit";queueCloudPersist()');
 await new Promise(resolve=>setImmediate(resolve));
 app.run('state.tournaments[0].name="second edit";queueCloudPersist();release()');
 await app.run('cloudPersistQueue');
 assert.equal(app.run('JSON.stringify(writes)'),JSON.stringify([{revision:10,name:'first edit'},{revision:11,name:'second edit'}]));
});
test('a saved form draft does not disable live registration updates forever',async()=>{
 const app=await fixture();
 app.run('dirtyFormDraftKeys.add("old-form");hasEditableFocus=()=>false;lastUserInteractionAt=0;');
 assert.equal(app.run('canRunLiveSharedRefresh()'),true);
});
