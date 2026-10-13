const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const plain = value => value && typeof value === 'object' && !Array.isArray(value);
const keyed = value => Array.isArray(value) && value.every(item => plain(item) && typeof item.id === 'string' && item.id) && new Set(value.map(item => item.id)).size === value.length;
export function tournamentChanges(before, after, path = []) {
  if (equal(before, after)) return [];
  if (plain(before) && plain(after)) return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap(key =>
    tournamentChanges(before[key], after[key], [...path, {key}]));
  if (keyed(before) && keyed(after)) {
    const old = new Map(before.map(item => [item.id, item]));
    const next = new Map(after.map(item => [item.id, item]));
    const common = new Set([...old.keys()].filter(id => next.has(id)));
    const oldOrder = before.map(item=>item.id).filter(id=>common.has(id));
    const nextOrder = after.map(item=>item.id).filter(id=>common.has(id));
    const orderChange = equal(oldOrder,nextOrder) ? [] : [{path,orderBefore:oldOrder,orderAfter:nextOrder}];
    return [...orderChange,...[...new Set([...old.keys(), ...next.keys()])].flatMap(id => tournamentChanges(old.get(id), next.get(id), [...path, {id}]))];
  }
  return [{path, beforeExists: before !== undefined, afterExists: after !== undefined, before, after}];
}
export function applyTournamentChanges(current, changes) {
  const result = structuredClone(current);
  if (!Array.isArray(changes) || changes.length > 10000) throw new Error('Invalid tournament changes.');
  for (const change of changes) {
    if (!Array.isArray(change.path) || !change.path.length || change.path.length > 30) throw new Error('Invalid change path.');
    let parent = result;
    if (Array.isArray(change.orderBefore) || Array.isArray(change.orderAfter)) {
      if (!Array.isArray(change.orderBefore) || !Array.isArray(change.orderAfter) || [...change.orderBefore,...change.orderAfter].some(id=>typeof id!=='string')) throw new Error('Invalid record order.');
      if (new Set(change.orderBefore).size!==change.orderBefore.length || new Set(change.orderAfter).size!==change.orderAfter.length || !equal([...change.orderBefore].sort(),[...change.orderAfter].sort())) throw new Error('Invalid record order.');
      for (const part of change.path) {
        if (Object.hasOwn(part,'id')) {
          if (!Array.isArray(parent)) throw new Error('Invalid record path.');
          const index=parent.findIndex(item=>item?.id===part.id);
          if (index<0) throw Object.assign(new Error('This record was removed. Refresh before editing.'),{code:'edit_conflict'});
          parent=parent[index];
        } else {
          if (!plain(parent) || typeof part.key!=='string' || ['__proto__','constructor','prototype'].includes(part.key)) throw new Error('Invalid field path.');
          parent=parent[part.key];
        }
      }
      if (!keyed(parent)) throw new Error('Invalid record order target.');
      const present=new Set(parent.map(item=>item.id));
      const current=parent.map(item=>item.id).filter(id=>change.orderBefore.includes(id));
      const expected=change.orderBefore.filter(id=>present.has(id));
      if (!equal(current,expected)) throw Object.assign(new Error('Someone reordered these records. Refresh and review your edit.'),{code:'edit_conflict'});
      const rank=new Map(change.orderAfter.filter(id=>present.has(id)).map((id,index)=>[id,index]));
      parent.sort((a,b)=>(rank.get(a.id) ?? Number.MAX_SAFE_INTEGER)-(rank.get(b.id) ?? Number.MAX_SAFE_INTEGER));
      continue;
    }
    for (let index = 0; index < change.path.length; index++) {
      const part = change.path[index];
      if (!part || Object.keys(part).length !== 1) throw new Error('Invalid change path.');
      let key;
      if (Object.hasOwn(part, 'id')) {
        if (!Array.isArray(parent) || typeof part.id !== 'string') throw new Error('Invalid record path.');
        const matches = parent.filter(item => item?.id === part.id);
        if (matches.length > 1) throw new Error('Duplicate record identity.');
        key = parent.findIndex(item => item?.id === part.id);
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
      if (Object.hasOwn(part,'id')) {
        if (change.afterExists && desired?.id !== part.id) throw new Error('Record identity cannot change.');
        if (key < 0 && change.afterExists) parent.push(structuredClone(desired));
        else if (!change.afterExists && key >= 0) parent.splice(key,1);
        else parent[key] = structuredClone(desired);
      } else if (change.afterExists) parent[key] = structuredClone(desired);
      else delete parent[key];
    }
  }
  return result;
}
