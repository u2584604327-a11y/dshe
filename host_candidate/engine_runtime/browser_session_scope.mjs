// Process-generation policy for the original Connection credential seam.
// Do not delete/rotate the user's credential file. All unrelated credentials
// remain with their original provider. Only the original browser-session
// signing record lives in this runtime generation and expires with it.
const installed = new WeakSet();
export function scopeBrowserSession(credentials, credentialKey) {
  if (!credentials || typeof credentialKey !== 'function' || installed.has(credentials)) {
    throw new Error('BROWSER_SESSION_SCOPE_OWNER');
  }
  const key = credentialKey('client-connection', 'browser-session');
  if (typeof key !== 'string') throw new Error('BROWSER_SESSION_SCOPE_KEY');
  const names = ['readRecord', 'describeRecord', 'listRecords', 'modifyRecord', 'deleteRecord'];
  const original = new Map(names.map(name => {
    if (typeof credentials[name] !== 'function') throw new Error('BROWSER_SESSION_SCOPE_PROVIDER');
    return [name, credentials[name]];
  }));
  let record, closed = false, tail = Promise.resolve();
  const alive = () => { if (closed) throw new Error('BROWSER_SESSION_SCOPE_REVOKED'); };
  const clone = value => value === undefined ? undefined : structuredClone(value);
  installed.add(credentials);
  credentials.readRecord = function(requested) {
    if (requested !== key) return original.get('readRecord').call(this, requested);
    alive(); return Promise.resolve(clone(record));
  };
  credentials.describeRecord = function(requested) {
    if (requested !== key) return original.get('describeRecord').call(this, requested);
    alive(); return Promise.resolve(record ? {configured: true, writable: true, kind: record.kind} : {configured: false, writable: true});
  };
  credentials.listRecords = async function() {
    alive(); const rows = (await original.get('listRecords').call(this)).filter(row => row.key !== key);
    if (record) rows.push({key, kind: record.kind});
    return rows;
  };
  credentials.modifyRecord = function(requested, mutate) {
    if (requested !== key) return original.get('modifyRecord').call(this, requested, mutate);
    alive();
    const operation = tail.then(async () => {
      alive(); const next = await mutate(clone(record)); alive();
      if (next !== undefined) {
        // This adapter only stores the exact versioned signing record the
        // pinned original Connection emits. Never a general credential sink.
        if (next?.kind !== 'grant' || next.payload?.version !== 1 ||
            typeof next.payload.secret !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(next.payload.secret) ||
            Object.keys(next).sort().join(',') !== 'kind,payload' ||
            Object.keys(next.payload).sort().join(',') !== 'secret,version') throw new Error('BROWSER_SESSION_SCOPE_RECORD');
        record = clone(next);
      }
      return clone(record);
    });
    tail = operation.catch(() => {}); return operation;
  };
  credentials.deleteRecord = function(requested) {
    if (requested !== key) return original.get('deleteRecord').call(this, requested);
    alive(); const operation = tail.then(() => { alive(); record = undefined; });
    tail = operation.catch(() => {}); return operation;
  };
  return Object.freeze({revoke() { closed = true; record = undefined; }});
}
