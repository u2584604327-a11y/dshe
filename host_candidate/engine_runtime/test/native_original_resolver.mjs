// Host-only resolver integration. The actual native dlopen is a spy; never
// execute the ARM64 binary or report this as an Android binding acceptance.
// INSERT_PINNED_RESOURCE_CORE
receiveModules();
Object.defineProperty(process, 'platform', {value: 'android'});
Object.defineProperty(process, 'arch', {value: 'arm64'});
Object.defineProperty(process, 'execPath', {value: process.argv[2]});
process.getuid = () => 99001;
let bindingCalls = 0;
const internalIds = new Set(['internal/modules/esm/loader', 'internal/modules/cjs/loader',
  'internal/modules/helpers', 'internal/modules/esm/utils', 'internal/modules/esm/resolve']);
process.dlopen = (module, filename) => {
  if (filename !== path.join(path.dirname(process.execPath), 'libdsh_original_require_builtin.so')) throw Error('UNEXPECTED_DLOPEN');
  bindingCalls++;
  module.exports = {
    getNativeBindingInfo: () => ({mode:'test-spy',product:'require-builtin',backend:'napi',abi:'napi-v9'}),
    requireBuiltin: id => internalIds.has(id) ? {explicitTestSpy: true} : undefined,
    isAllowedInternalId: id => internalIds.has(id),
  };
};
const pageSize = 4096;
// INSERT_VERIFIED_NATIVE_OVERLAY
installReadonlyFilesystem();
const builtins = new Set(builtinModules.map(name => name.replace(/^node:/, '')));
registerHooks({
  resolve(request, context, next) {
    if (request.startsWith('node:') || builtins.has(request)) return next(request, context);
    const parent = context.parentURL?.startsWith('file:') ? fileURLToPath(context.parentURL) : ENTRY;
    const filename = resolveModule(request, parent, new Set(context.conditions));
    return {url:pathToFileURL(filename).href,format:nativeMapping.format(filename)??formatOf(filename),shortCircuit:true};
  },
  load(url, context, next) {
    if (url.startsWith('node:')) return next(url, context);
    const filename = filenameOf(new URL(url));
    const source = nativeMapping.source(filename)??files.get(filename);
    if(source===undefined)fail('ERR_MODULE_NOT_FOUND');
    return {format:nativeMapping.format(filename)??formatOf(filename),source,shortCircuit:true};
  },
});
const {createRequire} = await import('node:module');
const originalAddon = createRequire(pathToFileURL(ENTRY))('node-addon-require-builtin');
const info = originalAddon.getBindingInfo();
if (bindingCalls!==1 || info.bindingSource!=='optional-package' || info.platformPackageSuffix!=='android-arm64' ||
    info.backend!=='napi' || info.abi!=='napi-v9' || info.product!=='require-builtin') throw Error('ORIGINAL_LOADER_RESULT');
for(const id of internalIds) {
  if(!originalAddon.isAllowedInternalId(id)||!originalAddon.requireBuiltin(id)?.explicitTestSpy) throw Error('ORIGINAL_LOADER_API');
}
try {process.dlopen({filename:'/other.node'},'/untrusted/other.so');throw Error('DLOPEN_ESCAPED');}
catch(error) {if(error.code!=='E_DSH_ADDON_DLOPEN_DENIED')throw error;}
if(originalAddon.isAllowedInternalId('internal/child_process'))throw Error('INTERNAL_ID_ESCAPE');
try{originalAddon.requireBuiltin('internal/child_process');throw Error('INTERNAL_ID_ESCAPE');}
catch(error){if(error.code!=='E_DSH_ADDON_INTERNAL_ID_DENIED')throw error;}
console.log('ORIGINAL_ANDROID_ADDON_ORIGINAL_RESOLVER_WITH_MOCK_BINDING=PASS_HOST');
console.log('ORIGINAL_ANDROID_ADDON_ACTUAL_ARM64_DLOPEN=NOT_TESTED');
