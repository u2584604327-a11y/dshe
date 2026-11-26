// Appended to the pinned in-memory core, codec and owner adapter by the runner.
// Capability responses here are deliberate unit fixtures, never disk evidence.
installReadonlyFilesystem();
const entries=new Map(['/dsh-home','/dsh-workspace'].map(name=>[name,{directory:true,mode:0o700,mtime:0}]));
const initial=encodeSessionSnapshot(entries),notifications=[];let version=0n,acknowledged=0n,last,denyNext=false;
if(process.env.DSH_FS_TEST_MEMORY==='1'){
 const memory=installSessionFilesystem({files,directories,privateFiles:profileFiles,resolve:filenameOf});
 const file=await fs.promises.open('/dsh-home/no-durability','wx');await file.writeFile('x');
 await assert.rejects(()=>file.sync(),{code:'E_DSH_DURABLE_STORE_UNAVAILABLE'});await file.close();assert.equal(memory.durable,false);memory.close();
 process.stdout.write('OWNER_MEMORY_MODE_FSYNC_FALSE_DURABILITY=DENY_UNIT\n');process.exit(0);
}
const owner=installSessionFilesystem({files,directories,privateFiles:profileFiles,resolve:filenameOf,maxBytes:64,maxEntries:12,
 snapshotCapability:{version,bytes:initial,commit(bytes){if(denyNext)throw Object.assign(Error('E_TEST_COMMIT_UNCERTAIN'),{code:'E_TEST_COMMIT_UNCERTAIN'});const rows=decodeSessionSnapshot(bytes);for(const row of rows.values())row.data.fill(0);last=Buffer.from(bytes);acknowledged=++version;return version;}},
 notify(type,name){assert(acknowledged>0n);notifications.push([type,name,acknowledged]);}});
assert.equal(owner.durable,true);const api=await import('node:fs/promises');
await api.mkdir('/dsh-home/db',{recursive:true,mode:0o700});
const handle=await api.open('/dsh-home/db/tmp','wx',0o600);await handle.writeFile('first');await handle.sync();
await assert.rejects(()=>api.rename('/dsh-home/db/tmp','/dsh-home/db/record'),{code:'EBUSY'});
await handle.close();await api.rename('/dsh-home/db/tmp','/dsh-home/db/record');
const directory=await api.open('/dsh-home/db','r');const beforeSync=version;await directory.sync();assert(version>beforeSync);await directory.close();
assert.equal(await api.readFile('/dsh-home/db/record','utf8'),'first');assert.equal(fs.statSync('/dsh-home/db/record').mode&0o777,0o600);
assert.equal(fs.statSync('/dsh-home/db',{bigint:true}).mode&0o777n,0o700n);
const oldVersion=version,oldEvents=notifications.length;
await assert.rejects(()=>api.writeFile('/dsh-home/db/record',Buffer.alloc(65)),{code:'ENOSPC'});
assert.equal(await api.readFile('/dsh-home/db/record','utf8'),'first');assert.equal(version,oldVersion);assert.equal(notifications.length,oldEvents);
await assert.rejects(()=>api.writeFile('/dsh-runtime/escape','x'),{code:'EROFS'});
await assert.rejects(()=>api.writeFile('/proc/escape','x'),{code:'EACCES'});
await assert.rejects(()=>api.writeFile('/dsh-home/\ud800','x'),{code:'EILSEQ'});
await api.chmod('/dsh-home/db/record',0o400);await assert.rejects(()=>api.writeFile('/dsh-home/db/record','x'),{code:'EACCES'});await api.chmod('/dsh-home/db/record','600');
const decoded=decodeSessionSnapshot(last);assert.equal(decoded.get('/dsh-home/db/record').data.toString(),'first');for(const row of decoded.values())row.data.fill(0);
await api.mkdir('/dsh-home/remove/nested',{recursive:true});await api.writeFile('/dsh-home/remove/nested/value','x');await api.rm('/dsh-home/remove',{recursive:true});assert.equal(fs.existsSync('/dsh-home/remove'),false);
await api.mkdir('/dsh-home/no-search');await api.writeFile('/dsh-home/no-search/value','x');await api.chmod('/dsh-home/no-search',0);await assert.rejects(()=>api.readFile('/dsh-home/no-search/value'),{code:'EACCES'});await api.chmod('/dsh-home/no-search',0o700);await api.rm('/dsh-home/no-search',{recursive:true});
const primary='/dsh-home/db/record',alias='/dsh-home/db/alias';
await api.link(primary,alias);
assert.equal(fs.statSync(primary).ino,fs.statSync(alias).ino);assert.equal(fs.statSync(primary).nlink,2);
await assert.rejects(()=>api.link(primary,alias),{code:'EEXIST'});
await assert.rejects(()=>api.link(primary,'/dsh-workspace/foreign'),{code:'EXDEV'});
await assert.rejects(()=>api.rename(alias,'/dsh-workspace/foreign'),{code:'EXDEV'});
await api.rename(primary,alias);assert.equal(fs.statSync(primary).nlink,2);
await api.writeFile(alias,'via alias');assert.equal(await api.readFile(primary,'utf8'),'via alias');
await assert.rejects(()=>api.writeFile(alias,Buffer.alloc(65)),{code:'ENOSPC'});
assert.equal(fs.statSync(primary).ino,fs.statSync(alias).ino);
const aliases=decodeSessionSnapshot(last);
assert.equal(last.subarray(0,8).toString(),'DSHFS002');
assert.equal(aliases.get(primary).link,alias);
assert.equal(aliases.get(alias).data.toString(),'via alias');
aliases.get(alias).data.fill(0);
await api.unlink(alias);assert.equal(fs.statSync(primary).nlink,1);assert.equal(await api.readFile(primary,'utf8'),'via alias');
assert.equal(last.subarray(0,8).toString(),'DSHFS001');
const corrupt=Buffer.concat([initial,Buffer.from([0])]);assert.throws(()=>decodeSessionSnapshot(corrupt),{code:'E_DSH_SNAPSHOT_ROOTS'});
const eventsBeforeFailure=notifications.length;denyNext=true;
await assert.rejects(()=>api.writeFile('/dsh-home/db/record','changed'),{code:'E_TEST_COMMIT_UNCERTAIN'});
assert.equal(notifications.length,eventsBeforeFailure);assert.equal(profileFiles.size,0);assert.throws(()=>fs.statSync('/dsh-home/db/record'),{code:'E_DSH_SESSION_FS_REVOKED'});
owner.close();initial.fill(0);last.fill(0);
process.stdout.write('OWNER_FILESYSTEM_ROLLBACK_ACK_ORDER_QUOTA_PERMISSION_REVOKE=PASS_UNIT\n');
