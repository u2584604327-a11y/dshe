// Appended by the runner to the real pinned filesystem core and adapter.
// The native /dsh-runtime directory must not exist; no original data is used.
files.set(ROOT + '/sample.txt', Buffer.from('abc'));
directories.add(ROOT + '/folder');
installReadonlyFilesystem();
installVirtualDirectories();
const api = await import('node:fs/promises');
const rejects = async (operation, code) => {
  try { await operation(); } catch (cause) { assert.equal(cause.code, code); return; }
  assert.fail('invalid directory operation accepted');
};
const directory = await api.opendir(new URL('file:///dsh-runtime'));
assert(directory instanceof fs.Dir);
assert.equal(directory.path, ROOT);
const first = await directory.read();
assert(first instanceof fs.Dirent);
assert.equal(first.name, 'folder');assert(first.isDirectory());assert(!first.isFile());
assert.equal(first.parentPath, ROOT);
let sync = true;
const second = await new Promise((resolve, reject) => {
  directory.read((error, value) => { assert(!sync); error ? reject(error) : resolve(value); });
  sync = false;
});
assert.equal(second.name, 'sample.txt');assert(second.isFile());assert(!second.isDirectory());
assert.equal(await directory.read(), null);assert.equal(directory.readSync(), null);
await directory.close();await rejects(() => directory.read(), 'ERR_DIR_CLOSED');
await rejects(() => directory.close(), 'ERR_DIR_CLOSED');
const buffered = fs.opendirSync(ROOT, {encoding: 'buffer'});
assert(Buffer.isBuffer(buffered.readSync().name));buffered.closeSync();
await rejects(() => buffered.readSync(), 'ERR_DIR_CLOSED');
const callback = await new Promise((resolve, reject) => fs.opendir(ROOT, (e, d) => e ? reject(e) : resolve(d)));
assert(callback instanceof fs.Dir);
for await (const entry of callback) { assert.equal(entry.name, 'folder'); break; }
await rejects(() => callback.read(), 'ERR_DIR_CLOSED');
const root = fs.opendirSync('/');const rootNames = [];
for (;;) { const entry = root.readSync(); if (!entry) break; rootNames.push(entry.name); }
root.closeSync();assert.deepEqual(rootNames, ['dsh-home', 'dsh-runtime', 'dsh-workspace']);
await rejects(() => api.opendir('/proc'), 'EACCES');
await rejects(() => api.opendir(ROOT + '/../../proc'), 'EACCES');
await rejects(() => api.opendir(ROOT + '/absent'), 'ENOENT');
await rejects(() => api.opendir(ROOT + '/sample.txt'), 'ENOTDIR');
await rejects(() => api.opendir(ROOT, {recursive: true}), 'ENOTSUP');
await rejects(() => api.opendir(ROOT, {bufferSize: 0}), 'ERR_OUT_OF_RANGE');
await rejects(() => api.opendir(ROOT, {encoding: 'bad-encoding'}), 'ERR_INVALID_ARG_VALUE');
await rejects(() => fs.openSync(ROOT + '/sample.txt'), 'E_DSH_DESCRIPTOR_API_UNAVAILABLE');
await rejects(() => api.mkdir(ROOT + '/unauthorized'), 'EROFS');
process.stdout.write('SEALED_DIRECTORY_PUBLIC_API_LIFECYCLE_AND_HOST_PATH_NEGATIVES=PASS\n');
