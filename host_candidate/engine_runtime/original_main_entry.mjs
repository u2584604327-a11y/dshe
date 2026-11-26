// Full original runCli for a fresh web profile, with sealed resources and an
// explicit durable owner capability. No EngineManager/P47 authorization here.
let mainTransport,mainFilesystem;
const mainOwnerAbort=new AbortController(),mainBrowserScopes=new Set();
function revokeMainOwner(){mainOwnerAbort.abort();for(const scope of mainBrowserScopes)scope.revoke();mainBrowserScopes.clear();mainFilesystem?.close();}
function originalWebDefaultPort(){
  const patch=files.get(ROOT+'/node_modules/@deepseek-ai/dsh-web-app/cordis.patch.yml');
  const ports=[...(patch?.toString('utf8')??'').matchAll(/^[ \t]+port: !!js ctx\.webStartup\.port \?\? ([1-9]\d{0,4})$/gm)];
  if(ports.length!==1||Number(ports[0][1])>65535)fail('E_DSH_ORIGINAL_WEB_PORT');
  return Number(ports[0][1]);
}
async function runOriginalMain(){
  const pageSize=4096; // artifact is restricted to the verified 4 KiB original ELF
  receiveModules();
  // INSERT_FIXED_ORIGINAL_NATIVE_MAPPING
  mainTransport=await installProfileTransport({onFailure:revokeMainOwner,originalDefaultPort:originalWebDefaultPort()});
  const snapshot=await mainTransport.filesystem.ready;
  installReadonlyFilesystem();installVirtualDirectories();
  let watches;
  mainFilesystem=installSessionFilesystem({files,directories,privateFiles:profileFiles,resolve:filenameOf,
    notify:(...args)=>watches?.notify(...args),snapshotCapability:{...snapshot,commit:mainTransport.filesystem.commit}});snapshot.bytes.fill(0);
  watches=installVirtualWatchers({resolve:filenameOf,stat:fs.statSync,signal:mainOwnerAbort.signal});
  // A writable temp namespace must not enable the original loader's native
  // cache/local build paths. Only the verified fixed native mapping is allowed.
  process.env.TMPDIR='/dsh-home/tmp';process.env.NARB_DISABLE_NATIVE_CACHE='1';process.env.NARB_DISABLE_LOCAL_BUILD='1';
  fs.mkdirSync('/dsh-home/tmp',{recursive:true,mode:0o700});
  // INSERT_ORIGINAL_MODULE_HOOKS
  const {Service}=await import('file:///dsh-runtime/node_modules/@deepseek-ai/cordis/lib/index.js');
  const {credentialKey}=await import('file:///dsh-runtime/node_modules/@deepseek-ai/dsh-credentials/lib/index.js');
  const {LocalCredentialProvider}=await import('file:///dsh-runtime/node_modules/@deepseek-ai/dsh-credentials-local/lib/index.js');
  const initialize=LocalCredentialProvider.prototype[Service.init];
  if(typeof initialize!=='function')fail('E_DSH_CREDENTIAL_PROVIDER_INIT');
  LocalCredentialProvider.prototype[Service.init]=async function*(...args){
    const scope=scopeBrowserSession(this,credentialKey);mainBrowserScopes.add(scope);
    try{
      yield* Reflect.apply(initialize,this,args);
      yield ()=>{scope.revoke();mainBrowserScopes.delete(scope);};
    }catch(cause){scope.revoke();mainBrowserScopes.delete(scope);throw cause;}
  };
  process.once('exit',revokeMainOwner);
  process.argv=[process.execPath,ENTRY,'--profile','web'];
  if(!mainTransport.omitPort)process.argv.push('--port',String(mainTransport.requestedPort));
  process.argv.push('--no-open');
  const entry=await import(pathToFileURL(ENTRY).href);
  if(typeof entry.runCli!=='function')fail('E_DSH_ORIGINAL_ENTRY_EXPORT');
  await entry.runCli();
  // Returning is not READY. The host must authenticate and exercise the actual
  // endpoint and required services; failures may be contained by Cordis.
  process.stdout.write('ORIGINAL_MAIN_ENTRY_RETURNED_NOT_READY_ATTESTATION\n');
}
runOriginalMain().catch(async cause=>{
  const code=typeof cause?.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(cause.code)?cause.code:'E_DSH_ORIGINAL_MAIN';
  process.stderr.write('ORIGINAL_MAIN_DENY='+code+'\n');process.exitCode=125;revokeMainOwner();await mainTransport?.close();
});
