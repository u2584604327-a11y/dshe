// HOST ONLY: the ARM64 dlopen is a deliberately identified spy. The five
// allowed loader objects come from the actual host Node --expose-internals.
// Never package this fixture, enable it by environment in the real bootstrap,
// or count it as Android/native/main-coroutine execution.
const {createRequire: internalRequireFactory}=await import('node:module');
const internalRequire=internalRequireFactory(import.meta.url);
const allowedInternals=new Set(['internal/modules/esm/loader','internal/modules/cjs/loader','internal/modules/helpers','internal/modules/esm/utils','internal/modules/esm/resolve']);
const hostInternals=new Map([...allowedInternals].map(id=>[id,internalRequire(id)]));
Object.defineProperty(process,'platform',{value:'android'});
Object.defineProperty(process,'arch',{value:'arm64'});
Object.defineProperty(process,'execPath',{value:process.argv[2]});process.getuid=()=>99001;
process.dlopen=(module,filename)=>{
 if(filename!==path.join(path.dirname(process.execPath),'libdsh_original_require_builtin.so'))throw Error('HOST_CONTROL_UNEXPECTED_DLOPEN');
 module.exports={getNativeBindingInfo:()=>({mode:'host-control-spy',product:'require-builtin',backend:'napi',abi:'napi-v9'}),
  requireBuiltin:id=>hostInternals.get(id),isAllowedInternalId:id=>allowedInternals.has(id)};
};
