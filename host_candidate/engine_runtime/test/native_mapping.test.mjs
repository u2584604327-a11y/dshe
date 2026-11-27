// A VM dependency test of the actual adapter. No Android ELF is executed here.
// Real original bytes/hashes, fake Android/installer syscalls and dlopen spy.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const source = fs.readFileSync(new URL('../original_native_mapping.mjs', import.meta.url), 'utf8');
const metadata = Object.fromEntries(Object.entries(fixture.metadata).map(([k,v])=>[k,Buffer.from(v,'base64')]));
const binary = Buffer.from(fixture.binary,'base64');
const original = Buffer.from('original engine JS unchanged');
const root = '/dsh-runtime/node_modules/node-addon-require-builtin-android-arm64';
const native = root + '/prebuilt/android-arm64-napi-v9.node';
const installed = '/data/app/verified/lib/arm64/libdsh_original_require_builtin.so';
let checks = 0;
async function prepare(options={}) {
  const calls=[];
  const fakeProcess={platform:options.platform??'android',arch:options.arch??'arm64',
    execPath:'/data/app/verified/lib/arm64/libdshnode_p21_exec.so',getuid:()=>options.uid??99001,
    dlopen(module,filename){calls.push(filename);if(options.loadFails)throw Object.assign(Error('FIXED_LOAD_FAILED'),{code:'FIXED_LOAD_FAILED'});module.exports={getNativeBindingInfo:()=>({mode:'vm-spy',product:'require-builtin',backend:'napi',abi:'napi-v9'}),requireBuiltin:id=>({testFixture:true,id}),isAllowedInternalId:()=>true};}};
  const fakeFs={
    readFileSync(filename){assert.equal(filename,installed);return options.binary??binary;},
    realpathSync(filename){return options.symlink&&filename===installed?'/untrusted/alias':filename;},
    lstatSync(filename){assert.equal(filename,installed);return {isFile:()=>!options.directory,isSymbolicLink:()=>!!options.symlink,
      size:options.size??91840,mode:options.mode??0o100755};}
  };
  const context=vm.createContext({process:fakeProcess,Buffer,Map,Set});
  const module=new vm.SourceTextModule(source,{context});
  await module.link(specifier=>{
    const value=specifier==='node:fs'?fakeFs:specifier==='node:path'?path:{createHash};
    return new vm.SyntheticModule(specifier==='node:crypto'?['createHash']:['default'],function(){
      this.setExport(specifier==='node:crypto'?'createHash':'default',specifier==='node:crypto'?createHash:value);
    },{context});
  });
  await module.evaluate();
  const files=new Map([['/dsh-runtime/original.js',original]]),directories=new Set(['/dsh-runtime']);
  if(options.collision)files.set(root+'/index.js',Buffer.from('never overwrite'));
  return {files,directories,process:fakeProcess,calls,install:module.namespace.installOriginalAndroidNativeMapping};
}
function denied(operation,code){assert.throws(operation,error=>error.code===code);checks++;}
for (const [options,code] of [
  [{platform:'linux'},'E_DSH_ADDON_RUNTIME'],[{arch:'x64'},'E_DSH_ADDON_RUNTIME'],
  [{uid:10001},'E_DSH_ADDON_RUNTIME'],[{uid:100000},'E_DSH_ADDON_RUNTIME'],
  [{symlink:true},'E_DSH_ADDON_INSTALLER_FILE'],[{directory:true},'E_DSH_ADDON_INSTALLER_FILE'],
  [{size:91839},'E_DSH_ADDON_INSTALLER_FILE'],[{mode:0o100777},'E_DSH_ADDON_INSTALLER_FILE'],
  [{binary:Buffer.from(binary.map((v,i)=>i===0?v^1:v))},'E_DSH_ADDON_NATIVE_SHA'],
  [{collision:true},'E_DSH_ADDON_NAMESPACE_COLLISION'],
]) {
  const p=await prepare(options),before=[...p.files];
  denied(()=>p.install(p.files,p.directories,metadata,4096),code);
  assert.deepEqual([...p.files],before);assert.equal(p.calls.length,0);checks+=2;
}
for(const page of [16384,8192,0,undefined,'4096']) {
  const p=await prepare();denied(()=>p.install(p.files,p.directories,metadata,page),'E_DSH_ADDON_RUNTIME');
}
for(const invalid of [{}, {...metadata,extra:Buffer.from('x')}, {...metadata,'index.js':Buffer.from('altered')}, {...metadata,'index.js':'not bytes'}]) {
  const p=await prepare();denied(()=>p.install(p.files,p.directories,invalid,4096),
    Object.keys(invalid).length!==3?'E_DSH_ADDON_METADATA':'E_DSH_ADDON_METADATA_SHA');
  assert.equal(p.files.size,1);checks++;
}
for(const uid of [99001,299001]) {
  const p=await prepare({uid});const mapping=p.install(p.files,p.directories,metadata,4096);
  assert.equal(p.files.size,5);assert.equal(p.files.get('/dsh-runtime/original.js'),original);checks+=2;
  for(const [name,bytes] of Object.entries(metadata)){assert.deepEqual(p.files.get(root+'/'+name),bytes);checks++;}
  assert.deepEqual(p.files.get(native),binary);assert(p.directories.has(root+'/prebuilt'));checks+=2;
  assert.equal(mapping.format(native),'commonjs');assert.equal(mapping.format('/dsh-runtime/other.node'),undefined);
  assert.equal(mapping.source('/dsh-runtime/other.node'),undefined);checks+=3;
  const shim=mapping.source(native);assert.match(shim.toString(),/process[.]dlopen\(module, /);shim.fill(0);
  assert.notEqual(mapping.source(native)[0],0);checks+=2;
  denied(()=>p.install(p.files,p.directories,metadata,4096),'E_DSH_ADDON_MAPPING_REPLAY');
  denied(()=>p.process.dlopen({filename:native},'/untrusted/other.so'),'E_DSH_ADDON_DLOPEN_DENIED');
  denied(()=>p.process.dlopen({filename:'/other.node'},installed),'E_DSH_ADDON_DLOPEN_DENIED');
  denied(()=>p.process.dlopen({filename:native},installed,2),'E_DSH_ADDON_DLOPEN_DENIED');
  denied(()=>{p.process.dlopen=()=>{};},undefined); // immutable capability
  const nativeModule={filename:native};
  vm.runInNewContext(mapping.source(native).toString(),{process:p.process,module:nativeModule});
  assert.deepEqual(p.calls,[installed]);assert.equal(nativeModule.exports.requireBuiltin('internal/modules/esm/loader').testFixture,true);checks+=2;
  denied(()=>nativeModule.exports.requireBuiltin('internal/child_process'),'E_DSH_ADDON_INTERNAL_ID_DENIED');
  assert.equal(nativeModule.exports.isAllowedInternalId('internal/bootstrap/realm'),false);checks++;
  denied(()=>{nativeModule.exports.requireBuiltin=()=>{};},undefined);
  denied(()=>p.process.dlopen({filename:native},installed),'E_DSH_ADDON_DLOPEN_DENIED');
}
{
  const p=await prepare({loadFails:true});p.install(p.files,p.directories,metadata,4096);
  denied(()=>p.process.dlopen({filename:native},installed),'FIXED_LOAD_FAILED');
  denied(()=>p.process.dlopen({filename:native},installed),'E_DSH_ADDON_DLOPEN_DENIED');
}
console.log('ORIGINAL_ANDROID_ADDON_MAPPING_ORIGINAL_BYTES_AND_CLOSED_DLOPEN=PASS_VM checks='+checks);
console.log('ORIGINAL_ANDROID_ADDON_REAL_ARM64_BINDING_AND_MAIN_PROFILE=NOT_TESTED');
