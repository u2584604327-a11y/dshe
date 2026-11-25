// The original Android supplement has its own immutable closure, outside
// engine.bin. This adapter is not a launcher or a P47 authorization.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';

const PACKAGE = 'node-addon-require-builtin-android-arm64';
const VIRTUAL_ROOT = '/dsh-runtime/node_modules/' + PACKAGE;
const NATIVE = 'prebuilt/android-arm64-napi-v9.node';
const ALIAS = 'libdsh_original_require_builtin.so';
const SHA = 'b69021cecbe48a62395b6a30c4975d17c4277ccb2429adada78dd74bc0fb0c44';
const MEMBERS = Object.freeze({
  'index.js': [128, 'b0f0f140e07303b7104192db9f8791a1e057b2a974934dcc7415fd9aff2f79e8'],
  'package.json': [429, 'e748d9d530986a873b80befa97de55b67f7ee09c1afdb0e53475111907ca762e'],
  'prebuilds.json': [221, '8fbaec402a97f535675abb10fd8b9f76eb7beb29449518fb7f00894abe0093e6'],
});
const readNative = fs.readFileSync.bind(fs);
const realpathNative = fs.realpathSync.bind(fs);
const statNative = fs.lstatSync.bind(fs);
const dlopenNative = process.dlopen;
const INTERNAL_IDS = new Set(['internal/modules/esm/loader', 'internal/modules/cjs/loader',
  'internal/modules/helpers', 'internal/modules/esm/utils', 'internal/modules/esm/resolve']);
let installed = false;
function deny(code) { const error = new Error(code); error.code = code; throw error; }

// Call before installing the virtual filesystem. The only real file allowed
// here is the fixed installer-owned sibling of the already verified Node ELF.
// The caller must also verify the original archive, ELF dependencies/page size
// and installation origin in its authenticated Android supervisor.
export function installOriginalAndroidNativeMapping(files, directories, metadata, pageSize) {
  if (installed) deny('E_DSH_ADDON_MAPPING_REPLAY');
  if (process.platform !== 'android' || process.arch !== 'arm64' ||
      typeof process.getuid !== 'function' || !Number.isSafeInteger(process.getuid()) || process.getuid() < 0 || process.getuid() % 100000 < 90000 || process.getuid() % 100000 > 99999 ||
      pageSize !== 4096) deny('E_DSH_ADDON_RUNTIME');
  if (!(files instanceof Map) || !(directories instanceof Set) || !metadata ||
      Object.keys(metadata).sort().join('\0') !== Object.keys(MEMBERS).sort().join('\0')) deny('E_DSH_ADDON_METADATA');
  const staged = new Map();
  for (const [name, [size, sha]] of Object.entries(MEMBERS)) {
    const bytes = metadata[name];
    if (!Buffer.isBuffer(bytes) || bytes.length !== size ||
        createHash('sha256').update(bytes).digest('hex') !== sha) deny('E_DSH_ADDON_METADATA_SHA');
    staged.set(VIRTUAL_ROOT + '/' + name, Buffer.from(bytes));
  }
  const nativePath = path.join(path.dirname(process.execPath), ALIAS);
  const nativeInfo = statNative(nativePath);
  if (realpathNative(nativePath) !== nativePath ||
      !nativeInfo.isFile() || nativeInfo.isSymbolicLink() || nativeInfo.size !== 91840 ||
      (nativeInfo.mode & 0o022) !== 0) deny('E_DSH_ADDON_INSTALLER_FILE');
  const binary = readNative(nativePath);
  if (binary.length !== 91840 || createHash('sha256').update(binary).digest('hex') !== SHA) deny('E_DSH_ADDON_NATIVE_SHA');
  const virtualNative = VIRTUAL_ROOT + '/' + NATIVE;
  staged.set(virtualNative, binary);
  // Never overwrite an engine member or a previously installed supplement.
  if ([...files.keys(), ...directories].some(name => name === VIRTUAL_ROOT || name.startsWith(VIRTUAL_ROOT + '/'))) {
    deny('E_DSH_ADDON_NAMESPACE_COLLISION');
  }
  const descriptor = Object.getOwnPropertyDescriptor(process, 'dlopen');
  if (!descriptor?.configurable || !descriptor.writable) deny('E_DSH_ADDON_DLOPEN_DESCRIPTOR');
  let opened = false;
  const guarded = function(module, filename, flags) {
    if (opened || filename !== nativePath || module?.filename !== virtualNative || flags !== undefined) deny('E_DSH_ADDON_DLOPEN_DENIED');
    opened = true; // A failed real load also consumes this fixed capability.
    const result = Reflect.apply(dlopenNative, process, [module, nativePath]);
    const raw = module.exports;
    if (!raw || ['requireBuiltin', 'isAllowedInternalId', 'getNativeBindingInfo'].some(name => typeof raw[name] !== 'function')) deny('E_DSH_ADDON_EXPORTS');
    const info = raw.getNativeBindingInfo();
    if (typeof info?.mode !== 'string' || info.product !== 'require-builtin' || info.backend !== 'napi' || info.abi !== 'napi-v9') deny('E_DSH_ADDON_BINDING_INFO');
    const publicInfo = Object.freeze({mode: info.mode, product: info.product, backend: info.backend, abi: info.abi});
    // The original require-builtin product accepts ANY internal id. Expose
    // only the five ids used by the pinned original app-boot. The native raw
    // exports never enter the CommonJS cache or the original public loader.
    const limited = {};
    Object.defineProperties(limited, {
      requireBuiltin: {enumerable: true, value(id) {
        if (!INTERNAL_IDS.has(id)) deny('E_DSH_ADDON_INTERNAL_ID_DENIED');
        return raw.requireBuiltin(id);
      }},
      isAllowedInternalId: {enumerable: true, value: id => INTERNAL_IDS.has(id) && raw.isAllowedInternalId(id) === true},
      getNativeBindingInfo: {enumerable: true, value: () => publicInfo},
    });
    module.exports = limited; // Original loader may attach its own metadata.
    return result;
  };
  Object.defineProperty(process, 'dlopen', {value: guarded, writable: false, configurable: false, enumerable: descriptor.enumerable});
  for (const [name, bytes] of staged) files.set(name, bytes);
  for (const filename of staged.keys()) {
    for (let parent = path.dirname(filename); parent !== '/dsh-runtime'; parent = path.dirname(parent)) directories.add(parent);
  }
  installed = true;
  // Only this verified binary receives a CJS shim. All original JS/JSON bytes
  // are returned unchanged by the existing sealed resolver, and other .node
  // modules still fail its original format gate. No general dlopen hook exists.
  const source = Buffer.from('process.dlopen(module, ' + JSON.stringify(nativePath) + ');\n');
  return Object.freeze({
    format(filename) { return filename === virtualNative ? 'commonjs' : undefined; },
    source(filename) { return filename === virtualNative ? Buffer.from(source) : undefined; },
  });
}
