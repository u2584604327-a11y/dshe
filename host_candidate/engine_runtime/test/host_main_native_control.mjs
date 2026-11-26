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

// Runs through the original JSONL plugin with the same authenticated snapshot
// transport as runCli. The generation comes only from the host test launcher.
async function exerciseOriginalJsonl(generation) {
 const load=name=>import(pathToFileURL(ROOT+'/node_modules/@deepseek-ai/'+name+'/lib/index.js').href);
 const {Context}=await load('cordis');
 const {apply}=await load('dsh-session-persistence-jsonl');
 const {SESSION_FORMAT_VERSION}=await load('dsh-session');
 const ctx=new Context(),peer=new Context();
 // Keep the first run eligible for the original first-use workspace check.
 const freshRoot='/dsh-home/jsonl-host-check',webRoot='/dsh-home/sessions';
 if(generation===1)await fs.promises.rename(freshRoot,webRoot);
 const config={root:generation===0?freshRoot:webRoot};
 const first=ctx.plugin({apply:scope=>apply(scope,config)});
 const second=peer.plugin({apply:scope=>apply(scope,config)});
 const id='owned-jsonl-control';
 const marker=(seq,text)=>({seq,type:'user/message',time:seq+1,surfaceOp:'append',
   data:{id:'msg'+seq,role:'user',source:{kind:'user'},content:[{type:'text',text}]}});
 let writer,reader;
 try{
  const target='/dsh-home/session-link-control',alias=target+'.alias';
  if(generation===0){
   await fs.promises.writeFile(target,'linked snapshot');
   await fs.promises.link(target,alias);
  }else{
   if(fs.statSync(alias).nlink!==2||fs.statSync(alias).ino!==fs.statSync(target).ino)fail('E_DSH_HOST_LINK_RESTORE');
   await fs.promises.writeFile(alias,'linked after restart');
   if(await fs.promises.readFile(target,'utf8')!=='linked after restart')fail('E_DSH_HOST_LINK_CONTENT');
   await fs.promises.unlink(alias);
  }
  await first.await();await second.await();
  const store=ctx.get('sessionPersistence'),other=peer.get('sessionPersistence');
  if(generation===0){
   if(await store.stat(id))fail('E_DSH_HOST_JSONL_FRESH');
   writer=await store.create({id,version:SESSION_FORMAT_VERSION,createdAt:1,cwd:'/dsh-workspace',
     isSeeded:false,delegationDepth:0});
   await writer.append([marker(0,'original durable message')]);
   await writer.flush();
  }else{
   if(generation!==1||!(await store.stat(id)))fail('E_DSH_HOST_JSONL_RESTART');
   writer=await store.open(id,'write');
   await writer.append([marker(1,'continued after restart')]);
   await writer.flush();
  }
  try{
   const duplicate=await other.open(id,'write');
   await duplicate.close();fail('E_DSH_HOST_JSONL_DOUBLE_WRITER');
  }catch(cause){
   if(cause?.name!=='SessionAlreadyOwnedError')throw cause;
  }
  await writer.close();writer=null;
  writer=await other.open(id,'write');await writer.close();writer=null;
  reader=await store.open(id,'read');
  const {events}=await reader.read();
  if(events.length!==generation+1||events[0]?.data?.content?.[0]?.text!=='original durable message'||
     (generation===1&&events[1]?.data?.content?.[0]?.text!=='continued after restart')){
   fail('E_DSH_HOST_JSONL_EVENT_RESTORE');
  }
 }finally{
  await reader?.close();await writer?.close();
  await second.dispose();await first.dispose();
 }
}
