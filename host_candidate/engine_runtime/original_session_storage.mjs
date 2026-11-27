// The main runtime holds the host snapshot root exclusively for one generation.
// The JSONL backend acquires a separate lease on its virtual lock handle.
function originalSessionStorageAdapter() {
  const filename = ROOT + '/node_modules/@deepseek-ai/dsh-session-persistence-jsonl/lib/index.js';
  const raw = files.get(filename);
  if (!raw || createHash('sha256').update(raw).digest('hex') !==
      '973dd78679b2661d6f492343bc22b124ae958aa597d3b36c698a2c650f909984') {
    fail('E_DSH_SESSION_STORAGE_SOURCE');
  }
  const source = raw.toString('utf8');
  const nativeImport = 'import { tryLockExclusive } from "@deepseek-ai/node-addon-system/flock";\n';
  const nativeCall = 'await tryLockExclusive(handle.fd);';
  if (source.split(nativeImport).length !== 2 || source.split(nativeCall).length !== 2) {
    fail('E_DSH_SESSION_STORAGE_LEASE_SEAM');
  }
  const adapted = Buffer.from(source.replace(nativeImport, '').replace(nativeCall,
    "await handle[Symbol.for('dsh.owner.sessionWriteLease')]();"));
  return name => name === filename ? adapted : undefined;
}
