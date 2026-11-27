// Original default-config execution from the verified immutable module stream.
// Profile initialization is bounded to fresh in-memory state, never host storage.
// The host supplies immutable resources. Entrypoint and argv are fixed here.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { builtinModules, registerHooks, syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = '/dsh-runtime';
const ENTRY = ROOT + '/node_modules/@deepseek-ai/dsh/lib/bin.js';
const EXPECTED_TREE = 'b2c7e52890351c4d1a3200c67ccb9be6154389a20da0b0b590d16676ce47b1e1';
const EXPECTED_MEMBERS = 30411;
const EXPECTED_BYTES = 262498938;
const files = new Map();
const profileFiles = new Map();
let profileBytes = 0;
const PROFILE = '/dsh-home/profiles/web';
const directories = new Set([ROOT, '/', '/dsh-home', '/dsh-workspace']);
const loaded = new Set();
const packageCache = new Map();
const originalRead = fs.readSync;
const readGate = new Int32Array(new SharedArrayBuffer(4));
let streamDeadline = 0n;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function exactBytes(length) {
  const bytes = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const count = streamRead(bytes, offset, length - offset);
    if (count === 0) fail('E_DSH_MODULE_STREAM_EOF');
    offset += count;
  }
  return bytes;
}

function streamRead(bytes, offset, length) {
  for (;;) {
    if (process.hrtime.bigint() >= streamDeadline) fail('E_DSH_MODULE_STREAM_TIMEOUT');
    try { return originalRead(0, bytes, offset, length, null); }
    catch (error) {
      if (error?.code === 'EINTR') continue;
      if (error?.code !== 'EAGAIN' && error?.code !== 'EWOULDBLOCK') throw error;
      // Android child stdio need not be blocking. The resource producer runs
      // outside this Node process; bounded futex waiting releases the CPU.
      Atomics.wait(readGate, 0, 0, 2);
    }
  }
}

function receiveModules() {
  streamDeadline = process.hrtime.bigint() + 80_000_000_000n;
  if (exactBytes(8).toString('ascii') !== 'DSHMOD01') fail('E_DSH_MODULE_STREAM_VERSION');
  const digest = createHash('sha256');
  digest.update('P54_IMMUTABLE_ENGINE_TREE_V1\0');
  const names = new Set();
  let members = 0;
  let total = 0;
  let addons = 0;
  for (;;) {
    const nameSize = exactBytes(4);
    const length = nameSize.readUInt32BE();
    if (length === 0) break;
    if (length > 4096 || ++members > EXPECTED_MEMBERS) fail('E_DSH_MODULE_STREAM_BOUND');
    const nameBytes = exactBytes(length);
    const name = nameBytes.toString('utf8');
    if (!Buffer.from(name, 'utf8').equals(nameBytes) || /[\\\x00-\x1f\x7f]/.test(name) ||
        name.split('/').some(part => !part || part === '.' || part === '..') || names.has(name)) {
      fail('E_DSH_MODULE_PATH');
    }
    names.add(name);
    const metadata = exactBytes(9);
    const directory = metadata[0];
    const size = metadata.readBigUInt64BE(1);
    if (directory > 1 || size > 128n * 1024n * 1024n || (directory && size !== 0n)) {
      fail('E_DSH_MODULE_TYPE_OR_SIZE');
    }
    total += Number(size);
    if (total > EXPECTED_BYTES) fail('E_DSH_MODULE_TOTAL_BOUND');
    const contents = exactBytes(Number(size));
    digest.update(nameSize);
    digest.update(nameBytes);
    digest.update(metadata);
    digest.update(createHash('sha256').update(contents).digest());
    const filename = ROOT + '/' + name;
    if (directory) directories.add(filename);
    else files.set(filename, contents);
    if (!directory && name.endsWith('.node')) addons++;
    for (let parent = path.dirname(filename); parent !== ROOT; parent = path.dirname(parent)) {
      directories.add(parent);
    }
  }
  const trailing = Buffer.alloc(1);
  if (streamRead(trailing, 0, 1) !== 0 || members !== EXPECTED_MEMBERS ||
      total !== EXPECTED_BYTES || addons !== 9 || digest.digest('hex') !== EXPECTED_TREE) {
    fail('E_DSH_MODULE_TREE_SEAL');
  }
}

function filenameOf(value) {
  let filename;
  if (value instanceof URL) filename = fileURLToPath(value);
  else if (Buffer.isBuffer(value)) filename = value.toString('utf8');
  else if (typeof value === 'string') filename = value;
  else fail('EINVAL');
  if (filename.includes('\0') || filename.includes('\\')) fail('EINVAL');
  const absolute = path.resolve('/dsh-workspace', filename);
  if (absolute === ROOT || absolute.startsWith(ROOT + '/') || absolute === '/' ||
      absolute === '/dsh-home' || absolute.startsWith('/dsh-home/') ||
      absolute === '/dsh-workspace' || absolute.startsWith('/dsh-workspace/')) return absolute;
  fail('EACCES');
}

function readFile(filename, options) {
  const name = filenameOf(filename);
  const contents = files.get(name) ?? profileFiles.get(name);
  if (contents === undefined) fail('ENOENT');
  const encoding = typeof options === 'string' ? options : options?.encoding;
  return encoding ? contents.toString(encoding) : Buffer.from(contents);
}

function stat(filename, options) {
  const name = filenameOf(filename);
  const directory = directories.has(name);
  const contents = files.get(name) ?? profileFiles.get(name);
  if (!directory && contents === undefined) {
    if (options?.throwIfNoEntry === false) return undefined;
    fail('ENOENT');
  }
  const number = value => options?.bigint ? BigInt(value) : value;
  const result = Object.create(fs.Stats.prototype);
  Object.assign(result, {
    dev: number(0), ino: number(0), mode: number(directory ? 0o40555 : 0o100444),
    nlink: number(1), uid: number(0), gid: number(0), rdev: number(0),
    size: number(directory ? 0 : contents.length), blksize: number(4096), blocks: number(0),
    atimeMs: number(0), mtimeMs: number(0), ctimeMs: number(0), birthtimeMs: number(0),
    atime: new Date(0), mtime: new Date(0), ctime: new Date(0), birthtime: new Date(0),
    isFile: () => !directory, isDirectory: () => directory, isSymbolicLink: () => false,
    isBlockDevice: () => false, isCharacterDevice: () => false,
    isFIFO: () => false, isSocket: () => false,
  });
  return result;
}

function realpath(filename, options) {
  stat(filename);
  const name = filenameOf(filename);
  return options === 'buffer' || options?.encoding === 'buffer' ? Buffer.from(name) : name;
}

function access(filename, mode = fs.constants.F_OK) {
  const result = stat(filename);
  if (mode & fs.constants.W_OK) fail('EROFS');
  if ((mode & fs.constants.X_OK) && !result.isDirectory()) fail('EACCES');
}

function readdir(filename, options) {
  const directory = filenameOf(filename);
  if (!stat(directory).isDirectory()) fail('ENOTDIR');
  const children = new Set();
  for (const name of [...directories, ...files.keys(), ...profileFiles.keys()]) {
    if (name !== directory && path.dirname(name) === directory) children.add(path.basename(name));
  }
  return [...children].sort().map(name => {
    const encoded = options === 'buffer' || options?.encoding === 'buffer' ? Buffer.from(name) : name;
    if (!options?.withFileTypes) return encoded;
    const information = stat(path.join(directory, name));
    return Object.assign(information, {name: encoded, parentPath: directory});
  });
}

function profilePath(filename) {
  const name = filenameOf(filename);
  if (name !== PROFILE && !name.startsWith(PROFILE + '/')) fail('EROFS');
  return name;
}

function mkdirProfile(filename, options) {
  const name = profilePath(filename);
  if (directories.has(name)) {
    if (!options?.recursive) fail('EEXIST');
    return undefined;
  }
  if (files.has(name) || profileFiles.has(name)) fail('EEXIST');
  if (!options?.recursive && !directories.has(path.dirname(name))) fail('ENOENT');
  let first;
  for (let current = name; !directories.has(current); current = path.dirname(current)) {
    if (directories.size > EXPECTED_MEMBERS + 256) fail('ENOSPC');
    if (profileFiles.has(current)) fail('ENOTDIR');
    directories.add(current); first = current;
  }
  return options?.recursive ? first : undefined;
}

function writeProfile(filename, data, options) {
  const name = profilePath(filename);
  if (!directories.has(path.dirname(name))) fail('ENOENT');
  if (directories.has(name)) fail('EISDIR');
  const encoding = typeof options === 'string' ? options : options?.encoding;
  const value = typeof data === 'string' ? Buffer.from(data, encoding) : Buffer.from(data);
  const flag = options?.flag ?? 'w';
  if (flag !== 'w' && flag !== 'wx') fail('EINVAL');
  if (flag === 'wx' && profileFiles.has(name)) fail('EEXIST');
  const total = profileBytes + value.length - (profileFiles.get(name)?.length ?? 0);
  if (total > 2 * 1024 * 1024 || (!profileFiles.has(name) && profileFiles.size >= 64)) fail('ENOSPC');
  profileFiles.set(name, value); profileBytes = total;
}

function callbackVersion(operation) {
  return (...args) => {
    const callback = args.pop();
    if (typeof callback !== 'function') fail('ERR_INVALID_ARG_TYPE');
    queueMicrotask(() => {
      let value;
      try { value = operation(...args); }
      catch (error) { callback(error); return; }
      callback(null, value);
    });
  };
}

function installReadonlyFilesystem() {
  const readers = {readFile, stat, lstat: stat, realpath, access, readdir,
    readlink: () => fail('EINVAL')};
  for (const [name, operation] of Object.entries(readers)) {
    fs[name + 'Sync'] = operation;
    fs[name] = callbackVersion(operation);
    fs.promises[name] = async (...args) => operation(...args);
  }
  fs.realpathSync.native = realpath;
  fs.realpath.native = fs.realpath;
  fs.existsSync = filename => {
    try { stat(filename); return true; }
    catch { return false; }
  };
  const denied = () => fail('EROFS');
  for (const name of ['writeFile', 'appendFile', 'mkdir', 'mkdtemp', 'rm', 'rmdir', 'unlink',
    'rename', 'copyFile', 'cp', 'truncate', 'chmod', 'chown', 'utimes', 'link', 'symlink']) {
    fs[name + 'Sync'] = denied;
    fs[name] = callbackVersion(denied);
    if (name in fs.promises) fs.promises[name] = async () => denied();
  }
  for (const [name, operation] of Object.entries({mkdir: mkdirProfile, writeFile: writeProfile})) {
    fs[name + 'Sync'] = operation;
    fs[name] = callbackVersion(operation);
    fs.promises[name] = async (...args) => operation(...args);
  }
  // Unsupported descriptor APIs retain the Node permission boundary on the
  // host and the isolated UID boundary on Android. No host paths are opened.
  fs.openSync = () => fail('E_DSH_DESCRIPTOR_API_UNAVAILABLE');
  fs.open = callbackVersion(fs.openSync);
  fs.promises.open = async () => fs.openSync();
  syncBuiltinESMExports();
}

function packageJson(directory) {
  if (packageCache.has(directory)) return packageCache.get(directory);
  const bytes = files.get(directory + '/package.json');
  const value = bytes === undefined ? null : JSON.parse(bytes.toString('utf8'));
  packageCache.set(directory, value);
  return value;
}

function packageScope(filename) {
  for (let directory = path.dirname(filename); directory.startsWith(ROOT); directory = path.dirname(directory)) {
    const manifest = packageJson(directory);
    if (manifest !== null) return {directory, manifest};
    if (directory === ROOT) break;
  }
  return null;
}

function fileOrDirectory(filename, depth = 0) {
  if (depth > 32) fail('E_DSH_MODULE_RESOLUTION_DEPTH');
  for (const candidate of [filename, filename + '.js', filename + '.json', filename + '.node']) {
    if (files.has(candidate)) return candidate;
  }
  if (directories.has(filename)) {
    const manifest = packageJson(filename);
    if (typeof manifest?.main === 'string') {
      const main = path.resolve(filename, manifest.main);
      if (main !== filename && (main === ROOT || main.startsWith(ROOT + '/'))) {
        try { return fileOrDirectory(main, depth + 1); }
        catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
      }
    }
    for (const extension of ['js', 'json', 'node']) {
      const index = filename + '/index.' + extension;
      if (files.has(index)) return index;
    }
  }
  fail('MODULE_NOT_FOUND');
}

function targetOf(target, conditions, replacement) {
  if (typeof target === 'string') return replacement === undefined ? target : target.replaceAll('*', replacement);
  if (target === null) return null;
  if (Array.isArray(target)) {
    for (const option of target) {
      const chosen = targetOf(option, conditions, replacement);
      if (chosen !== undefined) return chosen;
    }
    return undefined;
  }
  if (typeof target !== 'object') fail('ERR_INVALID_PACKAGE_TARGET');
  for (const [condition, option] of Object.entries(target)) {
    if (condition === 'default' || conditions.has(condition)) {
      const chosen = targetOf(option, conditions, replacement);
      if (chosen !== undefined) return chosen;
    }
  }
  return undefined;
}

function mappedTarget(mapping, subpath, conditions) {
  if (mapping === null || typeof mapping === 'string' || Array.isArray(mapping)) {
    return subpath === '.' ? targetOf(mapping, conditions) : undefined;
  }
  const keys = Object.keys(mapping);
  if (keys.every(key => !key.startsWith('.')) && !subpath.startsWith('#')) {
    return subpath === '.' ? targetOf(mapping, conditions) : undefined;
  }
  if (Object.hasOwn(mapping, subpath)) return targetOf(mapping[subpath], conditions);
  const patterns = keys.filter(key => key.includes('*')).sort((left, right) =>
    right.indexOf('*') - left.indexOf('*') || right.length - left.length);
  for (const pattern of patterns) {
    const [prefix, suffix] = pattern.split('*');
    if (subpath.startsWith(prefix) && subpath.endsWith(suffix) && subpath.length >= prefix.length + suffix.length) {
      return targetOf(mapping[pattern], conditions, subpath.slice(prefix.length, subpath.length - suffix.length));
    }
  }
  return undefined;
}

function packageTarget(directory, target) {
  if (typeof target !== 'string' || !target.startsWith('./') || /[\\\x00]/.test(target) ||
      target.slice(2).split('/').some(part => part === '..' || part === 'node_modules')) {
    fail('ERR_INVALID_PACKAGE_TARGET');
  }
  const filename = path.resolve(directory, target);
  if (!filename.startsWith(directory + '/')) fail('ERR_INVALID_PACKAGE_TARGET');
  if (!files.has(filename)) fail('MODULE_NOT_FOUND');
  return filename;
}

function resolveModule(request, parent, conditions, depth = 0) {
  if (depth > 32) fail('E_DSH_MODULE_RESOLUTION_DEPTH');
  if (request.startsWith('file:') || request.startsWith('/') || request.startsWith('.')) {
    const filename = request.startsWith('file:') ? filenameOf(new URL(request)) :
      filenameOf(path.resolve(path.dirname(parent), request));
    if (conditions.has('require')) return fileOrDirectory(filename);
    if (!files.has(filename)) fail('ERR_MODULE_NOT_FOUND');
    return filename;
  }
  const scope = packageScope(parent);
  if (request.startsWith('#')) {
    const target = scope && mappedTarget(scope.manifest.imports ?? {}, request, conditions);
    if (typeof target !== 'string') fail('ERR_PACKAGE_IMPORT_NOT_DEFINED');
    return target.startsWith('./') ? packageTarget(scope.directory, target) :
      resolveModule(target, parent, conditions, depth + 1);
  }
  const parts = request.split('/');
  const packageName = request.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  const subpath = '.' + request.slice(packageName.length);
  const candidates = [];
  if (scope?.manifest.name === packageName) candidates.push(scope.directory);
  for (let directory = path.dirname(parent); directory.startsWith(ROOT); directory = path.dirname(directory)) {
    if (path.basename(directory) !== 'node_modules') candidates.push(directory + '/node_modules/' + packageName);
    if (directory === ROOT) break;
  }
  for (const directory of candidates) {
    const manifest = packageJson(directory);
    if (manifest === null) continue;
    if (Object.hasOwn(manifest, 'exports')) {
      const target = mappedTarget(manifest.exports, subpath, conditions);
      if (target === undefined || target === null) fail('ERR_PACKAGE_PATH_NOT_EXPORTED');
      return packageTarget(directory, target);
    }
    return fileOrDirectory(subpath === '.' ? directory : directory + subpath.slice(1));
  }
  fail('ERR_MODULE_NOT_FOUND');
}

function formatOf(filename) {
  if (filename.endsWith('.json')) return 'json';
  if (filename.endsWith('.cjs')) return 'commonjs';
  if (filename.endsWith('.mjs')) return 'module';
  if (filename.endsWith('.node')) fail('E_DSH_NATIVE_ADDON_UNAVAILABLE');
  if (!filename.endsWith('.js')) fail('E_DSH_MODULE_FORMAT_UNAVAILABLE');
  return packageScope(filename)?.manifest.type === 'module' ? 'module' : 'commonjs';
}

async function run() {
  receiveModules();
  installReadonlyFilesystem();
  const builtins = new Set(builtinModules.map(name => name.replace(/^node:/, '')));
  registerHooks({
    resolve(request, context, next) {
      if (request.startsWith('node:') || builtins.has(request)) return next(request, context);
      const parent = context.parentURL?.startsWith('file:') ? fileURLToPath(context.parentURL) : ENTRY;
      const filename = resolveModule(request, parent, new Set(context.conditions));
      return {url: pathToFileURL(filename).href, format: formatOf(filename), shortCircuit: true};
    },
    load(url, context, next) {
      if (url.startsWith('node:')) return next(url, context);
      const filename = filenameOf(new URL(url));
      const source = files.get(filename);
      if (source === undefined) fail('ERR_MODULE_NOT_FOUND');
      loaded.add(filename);
      return {format: formatOf(filename), source, shortCircuit: true};
    },
  });
  const mode = process.env.DSH_ORIGINAL_CONFIG_MODE ?? 'default';
  if (mode !== 'default' && mode !== 'fresh-config') fail('E_DSH_CONFIG_MODE');
  process.argv = mode === 'default' ?
    [process.execPath, ENTRY, '--dump-default-config', '--profile', 'web'] :
    [process.execPath, ENTRY, '--profile', 'web', '--dump-config'];
  const entry = await import(pathToFileURL(ENTRY).href);
  if (typeof entry.runCli !== 'function') fail('E_DSH_ORIGINAL_ENTRY_EXPORT');
  await entry.runCli();
  process.stderr.write('DSH_ORIGINAL_CONFIG_MODULES=' + loaded.size + '\n');
}

run().catch(error => {
  const code = typeof error?.code === 'string' && /^[A-Z0-9_]{1,100}$/.test(error.code) ? error.code : 'E_DSH_MODULE_EXECUTION';
  process.stderr.write('DSH_ORIGINAL_CONFIG_ERROR=' + code + '\n');
  process.exitCode = 125;
});
