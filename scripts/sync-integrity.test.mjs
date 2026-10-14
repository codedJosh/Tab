import assert from 'node:assert/strict';
import test from 'node:test';
import {loadFrontendDomain} from './helpers/frontend-domain.mjs';

async function fixture(){
 const app=loadFrontendDomain();
 await app.run('getSeedState().then(value=>{state=value;session.userEmail="manager@test.org";session.cloudSessionToken="session";cloudRuntime.revision=10;})');
 app.run(`state.tournaments=[createTournamentRecord({name:"Test",format:"World Schools"})];var stored = new Map(); localStorageGet=key=>stored.get(key)||null;localStorageSet=(key,value)=>{stored.set(key,value);return true};localStorageRemove=key=>stored.delete(key);renderApp=()=>{};saveSession=()=>{};probeCloudBackend=async()=>true;getCurrentUser=()=>({email:session.userEmail});waitForCloudRetry=async()=>{};`);
 return app;
}
test('stale autosave rebases disjoint edits onto the latest workspace',async()=>{
 const app=await fixture();
 app.run(`var serverState=clone(state);serverState.appSettings.branding.accent='#remote-change';serverState.tournaments[0].teams.push({id:'remote-registration',name:'New team'});var writes=[];
 cloudConfirmedState=clone(state);state.tournaments[0].name='Local motion edit';
 callCloud=async(action,payload)=>{if(action==='persist'){writes.push(payload);if(writes.length===1)throw Object.assign(new Error('stale'),{code:'stale_revision'});serverState=clone(payload.state);return {revision:12}}if(action==='get_state')return {state:serverState,revision:11};throw new Error(action)};`);
 await app.run('queueCloudPersist(); cloudPersistQueue');
 assert.equal(app.run('writes.map(item=>item.expectedRevision).join(",")'),'10,11');
 assert.equal(app.run('serverState.tournaments[0].name'),'Local motion edit');
 assert.equal(app.run('serverState.appSettings.branding.accent'),'#remote-change');
 assert.equal(app.run('serverState.tournaments[0].teams.some(team=>team.id==="remote-registration")'),true);
 assert.equal(app.run('hasPendingCloudSyncForCurrentSession()'),false);
 assert.equal(app.run('stored.has(PENDING_CLOUD_SYNC_STORAGE_KEY)'),false);
});
test('an explicit deletion keeps its target deleted without erasing a concurrent registration',async()=>{
 const app=await fixture();
 app.run(`state.tournaments[0].teams=[{id:'remove-me',name:'Old team'}];cloudConfirmedState=clone(state);
 state.tournaments[0].teams=[];var serverState=clone(cloudConfirmedState);serverState.tournaments[0].teams.push({id:'new-registration',name:'New team'});var writes=0;
 callCloud=async(action,payload)=>{if(action==='persist'){writes++;if(writes===1)throw Object.assign(new Error('stale'),{code:'stale_revision'});serverState=clone(payload.state);return {revision:12}}if(action==='get_state')return {state:serverState,revision:11};throw new Error(action)};`);
 assert.equal(await app.run('persistStateToCloudNow()'),true);
 assert.equal(app.run('serverState.tournaments[0].teams.some(team=>team.id==="remove-me")'),false);
 assert.equal(app.run('serverState.tournaments[0].teams.some(team=>team.id==="new-registration")'),true);
});
test('offline snapshot without its base revision is preserved instead of replayed',async()=>{
 const app=await fixture();
 app.run('pendingCloudSync={id:"legacy",state:clone(state),userEmail:session.userEmail}');
 assert.equal(await app.run('preparePendingCloudSyncReplay()'),false);
 assert.equal(app.run('pendingCloudSync'),null);
 assert.equal(app.run('JSON.parse(stored.get(CLOUD_SYNC_CONFLICTS_STORAGE_KEY))[0].id'),'legacy');
});
test('pending backend saves retry in the current session after a transport failure',async()=>{
 const app=await fixture();
 app.run(`cloudConfirmedState=clone(state);state.tournaments[0].name='Saved offline';var calls=0;
 navigator.onLine=true;window.setTimeout=(fn,ms)=>setTimeout(fn,ms);window.clearTimeout=clearTimeout;
 callCloud=async(action,payload)=>{if(action!=='persist')throw new Error(action);calls++;if(calls===1)throw new TypeError('network unavailable');return {revision:11}};`);
 app.run('queueCloudPersist();');
 await app.run('cloudPersistQueue');
 assert.equal(app.run('hasPendingCloudSyncForCurrentSession()'),true);
 app.run('retryPendingCloudSyncNow()');
 await new Promise(resolve=>setTimeout(resolve,30));
 await app.run('cloudPersistQueue');
 assert.equal(app.run('calls'),2);
 assert.equal(app.run('hasPendingCloudSyncForCurrentSession()'),false);
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

test('tournament patch retries a timed-out idempotent edit without rerunning its mutation',async()=>{
 const app=await fixture();
 app.run(`let mutationRuns=0;let calls=[];callCloud=async(action,payload)=>{calls.push(payload.changes);if(calls.length===1)throw Object.assign(new Error('timeout'),{code:'backend_timeout'});return {revision:11,tournament:{...state.tournaments[0],name:'Saved name'}}};waitForCloudRetry=async()=>{};`);
 const result=await app.run(`persistTournamentMutationDurably(state.tournaments[0].id,tournament=>{mutationRuns++;tournament.name='Saved name';return tournament},'Saved')`);
 assert.equal(result,true);
 assert.equal(app.run('mutationRuns'),1);
 assert.equal(app.run('calls.length'),2);
 assert.equal(app.run('JSON.stringify(calls[0])===JSON.stringify(calls[1])'),true);
 assert.equal(app.run('state.tournaments[0].name'),'Saved name');
});

test('same-field tournament conflict keeps the attempted state and refreshes the saved state',async()=>{
 const app=await fixture();
 app.run(`var serverState=clone(state);serverState.tournaments[0].name='Other device value';callCloud=async()=>{throw Object.assign(new Error('Someone changed the same field.'),{code:'edit_conflict'})};refreshStateFromBackend=async()=>{state=clone(serverState);cloudRuntime.revision=11;return true};`);
 const result=await app.run(`persistTournamentMutationDurably(state.tournaments[0].id,tournament=>{tournament.name='My attempted value';return tournament},'Saved')`);
 assert.equal(result,false);
 assert.equal(app.run('state.tournaments[0].name'),'Other device value');
 assert.equal(app.run('JSON.parse(stored.get(CLOUD_SYNC_CONFLICTS_STORAGE_KEY))[0].state.tournaments[0].name'),'My attempted value');
});

test('an older state response cannot replace a newer acknowledged revision',async()=>{
 const app=await fixture();
 app.run(`state.tournaments[0].name='newer local value';var resolveRead;callCloud=()=>new Promise(resolve=>resolveRead=resolve);`);
 const refresh=app.run('refreshStateFromBackend({forceApply:true})');
 await new Promise(resolve=>setImmediate(resolve));
 app.run('cloudRuntime.revision=12');
 app.run(`resolveRead({revision:11,state:{...state,tournaments:[{...state.tournaments[0],name:'older response'}]}})`);
 assert.equal(await refresh,false);
 assert.equal(app.run('state.tournaments[0].name'),'newer local value');
 assert.equal(app.run('cloudRuntime.revision'),12);
});

test('system-manager saves patch changed fields onto the latest shared workspace',async()=>{
 const app=await fixture();
 app.run(`isSystemAdmin=()=>true;cloudConfirmedState=clone(state);var serverState=clone(state);serverState.appSettings.branding.accentDeep='#remote-change';var savedChanges;callCloud=async(action,payload)=>{savedChanges=payload.changes;serverState=applyTournamentChanges(serverState,payload.changes);return {revision:11}};state.appSettings.branding.accent='#local-change';`);
 app.run('queueCloudWorkspacePatch({successMessage:"Branding saved"})');
 await app.run('workspacePatchQueue');
 assert.equal(app.run('serverState.appSettings.branding.accent'),'#local-change');
 assert.equal(app.run('serverState.appSettings.branding.accentDeep'),'#remote-change');
 assert.equal(app.run('cloudConfirmedState.appSettings.branding.accent'),'#local-change');
 assert.equal(app.run('savedChanges.length'),1);
 assert.equal(app.run('cloudRuntime.revision'),10);
});
