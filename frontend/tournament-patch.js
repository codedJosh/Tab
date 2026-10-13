const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
const recordKey = value => {
  if (!Array.isArray(value)) return '';
  if (value.every(item => plain(item) && typeof item.id === 'string' && item.id) && new Set(value.map(item => item.id)).size === value.length) return 'id';
  if (value.every(item => plain(item) && Number.isInteger(Number(item.round)) && Number(item.round) > 0) && new Set(value.map(item => Number(item.round))).size === value.length) return 'round';
  return '';
};
const keyed = value => Boolean(recordKey(value));
const identity = (record, key) => key === 'round' ? Number(record?.round) : record?.id;
const isRecordPart = part => Object.hasOwn(part || {}, 'id') || Object.hasOwn(part || {}, 'round');
const recordPartKey = part => Object.hasOwn(part || {}, 'id') ? 'id' : 'round';
const findRecordIndex = (records, part) => {
  const key = recordPartKey(part);
  const target = key === 'round' ? Number(part.round) : part.id;
  return records.findIndex(item => identity(item, key) === target);
};
export function tournamentChanges(before, after, path = []) {
  if (equal(before, after)) return [];
  if (plain(before) && plain(after)) return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap(key =>
    tournamentChanges(before[key], after[key], [...path, {key}]));
  const beforeKey = recordKey(before);
  const afterKey = recordKey(after);
  const key = beforeKey === afterKey ? beforeKey : before?.length === 0 ? afterKey : after?.length === 0 ? beforeKey : '';
  if (key) {
    const old = new Map(before.map(item => [identity(item, key), item]));
    const next = new Map(after.map(item => [identity(item, key), item]));
    const common = new Set([...old.keys()].filter(id => next.has(id)));
    const oldOrder = before.map(item=>identity(item, key)).filter(id=>common.has(id));
    const nextOrder = after.map(item=>identity(item, key)).filter(id=>common.has(id));
    const orderChange = equal(oldOrder,nextOrder) ? [] : [{path,orderBefore:oldOrder,orderAfter:nextOrder}];
    return [...orderChange,...[...new Set([...old.keys(), ...next.keys()])].flatMap(id => {
      const recordPath = [...path, {[key]: id}];
      if (old.has(id) && !next.has(id)) return [{path: recordPath, removeRecord: true}];
      return tournamentChanges(old.get(id), next.get(id), recordPath);
    })];
  }
  return [{path, beforeExists: before !== undefined, afterExists: after !== undefined, before, after}];
}
export function applyTournamentChanges(current, changes) {
  const result = structuredClone(current);
  if (!Array.isArray(changes) || changes.length > 10000) throw new Error('Invalid tournament changes.');
  for (const change of changes) {
    if (!Array.isArray(change.path) || !change.path.length || change.path.length > 30) throw new Error('Invalid change path.');
    let parent = result;
    if (change.removeRecord === true) {
      const identityPart = change.path.at(-1);
      if (!isRecordPart(identityPart)) throw new Error('Invalid record removal.');
      for (const part of change.path.slice(0, -1)) {
        if (isRecordPart(part)) {
          if (!Array.isArray(parent)) throw new Error('Invalid record path.');
          const index = findRecordIndex(parent, part);
          if (index < 0) throw Object.assign(new Error('This record was removed. Refresh before editing.'),{code:'edit_conflict'});
          parent = parent[index];
        } else {
          if (!plain(parent) || typeof part.key !== 'string' || ['__proto__','constructor','prototype'].includes(part.key)) throw new Error('Invalid field path.');
          parent = parent[part.key];
        }
      }
      if (!Array.isArray(parent)) throw new Error('Invalid record removal target.');
      const removeIndex = findRecordIndex(parent, identityPart);
      if (removeIndex >= 0) parent.splice(removeIndex, 1);
      continue;
    }
    if (Array.isArray(change.orderBefore) || Array.isArray(change.orderAfter)) {
      if (!Array.isArray(change.orderBefore) || !Array.isArray(change.orderAfter) || [...change.orderBefore,...change.orderAfter].some(id=>typeof id!=='string' && !Number.isInteger(id))) throw new Error('Invalid record order.');
      if (new Set(change.orderBefore).size!==change.orderBefore.length || new Set(change.orderAfter).size!==change.orderAfter.length || !equal([...change.orderBefore].sort(),[...change.orderAfter].sort())) throw new Error('Invalid record order.');
      for (const part of change.path) {
        if (isRecordPart(part)) {
          if (!Array.isArray(parent)) throw new Error('Invalid record path.');
          const index=findRecordIndex(parent,part);
          if (index<0) throw Object.assign(new Error('This record was removed. Refresh before editing.'),{code:'edit_conflict'});
          parent=parent[index];
        } else {
          if (!plain(parent) || typeof part.key!=='string' || ['__proto__','constructor','prototype'].includes(part.key)) throw new Error('Invalid field path.');
          parent=parent[part.key];
        }
      }
      if (!keyed(parent)) throw new Error('Invalid record order target.');
      const identityKey=recordKey(parent);
      if (!identityKey) throw new Error('Invalid record order target.');
      const present=new Set(parent.map(item=>identity(item,identityKey)));
      const current=parent.map(item=>identity(item,identityKey)).filter(id=>change.orderBefore.includes(id));
      const expected=change.orderBefore.filter(id=>present.has(id));
      if (!equal(current,expected)) throw Object.assign(new Error('Someone reordered these records. Refresh and review your edit.'),{code:'edit_conflict'});
      const rank=new Map(change.orderAfter.filter(id=>present.has(id)).map((id,index)=>[id,index]));
      parent.sort((a,b)=>(rank.get(identity(a,identityKey)) ?? Number.MAX_SAFE_INTEGER)-(rank.get(identity(b,identityKey)) ?? Number.MAX_SAFE_INTEGER));
      continue;
    }
    for (let index = 0; index < change.path.length; index++) {
      const part = change.path[index];
      if (!part || Object.keys(part).length !== 1) throw new Error('Invalid change path.');
      let key;
      if (isRecordPart(part)) {
        if (!Array.isArray(parent)) throw new Error('Invalid record path.');
        const index = findRecordIndex(parent, part);
        const matches = index >= 0 ? [parent[index]] : [];
        if (matches.length > 1) throw new Error('Duplicate record identity.');
        key = index;
      } else {
        if (!plain(parent) || typeof part.key !== 'string' || ['__proto__','constructor','prototype'].includes(part.key)) throw new Error('Invalid field path.');
        key = part.key;
      }
      if (index < change.path.length - 1) {
        parent = parent[key];
        if (!parent) throw Object.assign(new Error('This record was removed. Refresh before editing.'),{code:'edit_conflict'});
        continue;
      }
      const existing = parent[key];
      const desired = change.afterExists ? change.after : undefined;
      if (equal(existing, desired)) continue; // Retrying an acknowledged change is harmless.
      if (!equal(existing, change.beforeExists ? change.before : undefined)) throw Object.assign(new Error('Someone changed the same field. Refresh and review your edit.'),{code:'edit_conflict'});
      if (isRecordPart(part)) {
        const identityKey = recordPartKey(part);
        const targetIdentity = identity(part, identityKey);
        if (identityKey === 'round' && (!Number.isInteger(targetIdentity) || targetIdentity <= 0)) throw new Error('Invalid record path.');
        const partIdentity = identityKey === 'round' ? Number(part.round) : part.id;
        if (change.afterExists && (identityKey === 'round' ? Number(desired?.round) !== partIdentity : desired?.id !== partIdentity)) throw new Error('Record identity cannot change.');
        if (key < 0 && change.afterExists) parent.push(structuredClone(desired));
        else if (!change.afterExists && key >= 0) parent.splice(key,1);
        else parent[key] = structuredClone(desired);
      } else if (change.afterExists) parent[key] = structuredClone(desired);
      else delete parent[key];
    }
  }
  return result;
}
