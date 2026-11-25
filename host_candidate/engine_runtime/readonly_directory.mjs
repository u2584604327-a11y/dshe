// Directory handles in the verified resource namespace. No native directory
// descriptor, host listing, filesystem permission or write capability is used.
export function installVirtualDirectories() {
  function opendir(filename, options) {
    const name = filenameOf(filename);
    if (!stat(name).isDirectory()) fail('ENOTDIR');
    if (options !== undefined && options !== null && typeof options !== 'string' && typeof options !== 'object') fail('ERR_INVALID_ARG_TYPE');
    if (options?.recursive) fail('ENOTSUP');
    if (options?.bufferSize !== undefined && (!Number.isInteger(options.bufferSize) || options.bufferSize < 1)) fail('ERR_OUT_OF_RANGE');
    const encoding = typeof options === 'string' ? options : options?.encoding ?? 'utf8';
    if (encoding !== 'buffer' && !Buffer.isEncoding(encoding)) fail('ERR_INVALID_ARG_VALUE');
    const entries = readdir(name, {encoding, withFileTypes: true}).map(information => {
      const entry = Object.create(fs.Dirent.prototype);
      entry.name = information.name; entry.parentPath = name;
      for (const type of ['File', 'Directory', 'SymbolicLink', 'BlockDevice', 'CharacterDevice', 'FIFO', 'Socket']) {
        entry['is' + type] = information['is' + type];
      }
      return entry;
    });
    let closed = false, cursor = 0;
    const readSync = () => {
      if (closed) fail('ERR_DIR_CLOSED');
      return entries[cursor++] ?? null;
    };
    const closeSync = () => {
      if (closed) fail('ERR_DIR_CLOSED');
      closed = true;
    };
    const method = operation => callback => {
      if (callback === undefined) return Promise.resolve().then(operation);
      if (typeof callback !== 'function') fail('ERR_INVALID_ARG_TYPE');
      queueMicrotask(() => {
        let result;
        try { result = operation(); } catch (error) { callback(error); return; }
        callback(null, result);
      });
    };
    const directory = Object.create(fs.Dir.prototype);
    Object.defineProperties(directory, {
      path: {value: name}, readSync: {value: readSync}, closeSync: {value: closeSync},
      read: {value: method(readSync)}, close: {value: method(closeSync)},
      [Symbol.asyncIterator]: {value: async function* () {
        try { for (;;) { const entry = readSync(); if (entry === null) return; yield entry; } }
        finally { if (!closed) closeSync(); }
      }},
    });
    return directory;
  }
  fs.opendirSync = opendir;
  fs.opendir = callbackVersion(opendir);
  fs.promises.opendir = async (...args) => opendir(...args);
  syncBuiltinESMExports();
}
