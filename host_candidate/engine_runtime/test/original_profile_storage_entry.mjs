// Actual original JSON backend, fresh owner data only. Not full main/READY.
let storageTransport,ownerFilesystem,storageStage='RESOURCE';
async function runOriginalStorage(){
  receiveModules();
  storageTransport=await installProfileTransport();
  const initial=await storageTransport.filesystem.ready;
  installReadonlyFilesystem();installVirtualDirectories();
  ownerFilesystem=installSessionFilesystem({files,directories,privateFiles:profileFiles,resolve:filenameOf,
    snapshotCapability:{...initial,commit:storageTransport.filesystem.commit}});initial.bytes.fill(0);
  // INSERT_ORIGINAL_MODULE_HOOKS
  storageStage='IMPORT';
  const {JsonStorageBackend}=await import('file:///dsh-runtime/node_modules/@deepseek-ai/dsh-storage-json/lib/index.js');
  const storage=new JsonStorageBackend('/dsh-home/storage');
  const generation=Number(process.env.DSH_STORAGE_TEST_GENERATION);
  if(generation!==0&&generation!==1)fail('E_DSH_TEST_GENERATION');
  for(const layout of ['single','per-record']){
    storageStage='OPEN';
    const unit=await storage.kv.open({name:layout==='single'?'testsingle':'testrecords',version:1,tables:['items'],hasGlobal:true,layout});
    storageStage='READ';
    const before=await unit.loadAll();
    if(generation===1&&(before.global?.generation!==0||before.tables.items.record?.value!=='original-json-backend'))fail('E_DSH_ORIGINAL_JSON_RESTORE');
    storageStage='PUBLISH';
    await unit.putRecord('items','record',{value:'original-json-backend'});
    await unit.setGlobal({generation});
    const after=await unit.loadAll();if(after.global?.generation!==generation||after.tables.items.record?.value!=='original-json-backend')fail('E_DSH_ORIGINAL_JSON_PUBLISH');
    await unit.close();
  }
  await storage.close();
  process.stdout.write('ORIGINAL_JSON_SINGLE_PER_RECORD_ATOMIC_FILE_AND_DIRECTORY_SYNC=PASS modules='+loaded.size+'\n');
  ownerFilesystem.close();await storageTransport.close();
}
runOriginalStorage().catch(async cause=>{
  const code=typeof cause?.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(cause.code)?cause.code:'E_DSH_ORIGINAL_STORAGE';
  process.stderr.write('ORIGINAL_STORAGE_DENY='+code+' stage='+storageStage+' kind='+(['Error','TypeError','RangeError'].includes(cause?.name)?cause.name:'OTHER')+'\n');
  for(const frame of String(cause?.stack??'').split('\n').filter(row=>/^\s+at /.test(row)).slice(0,3))process.stderr.write('ORIGINAL_STORAGE_TEST_FRAME='+frame+'\n');process.exitCode=125;ownerFilesystem?.close();await storageTransport?.close();
});
