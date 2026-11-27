// Virtual namespace watcher behavior. No native directory or Android claim.
installReadonlyFilesystem();
let watches;const controller=new AbortController();
const store=installSessionFilesystem({files,directories,privateFiles:profileFiles,resolve:filenameOf,notify:(...args)=>watches?.notify(...args)});
watches=installVirtualWatchers({resolve:filenameOf,stat:fs.statSync,signal:controller.signal,maxWatchers:3});
const api=await import('node:fs/promises');await api.mkdir('/dsh-home/dir');
const seen=[],watcher=fs.watch('/dsh-home',{recursive:true},(type,name)=>seen.push([type,name]));
await api.writeFile('/dsh-home/dir/file','x');await new Promise(resolve=>queueMicrotask(resolve));assert.deepEqual(seen,[['rename','dir/file']]);
const iterator=api.watch('/dsh-home/dir',{persistent:false});const next=iterator.next();await api.writeFile('/dsh-home/dir/file','y');assert.deepEqual(await next,{value:{eventType:'change',filename:'file'},done:false});await iterator.return();
const abort=new AbortController(),cancelled=api.watch('/dsh-home/dir',{signal:abort.signal});const pending=cancelled.next();abort.abort();await assert.rejects(()=>pending,{name:'AbortError',code:'ABORT_ERR'});
const already=AbortSignal.abort(),immediate=api.watch('/dsh-home',{signal:already});await assert.rejects(()=>immediate.next(),{code:'ABORT_ERR'});
assert.throws(()=>fs.watch('/proc'),{code:'EACCES'});assert.throws(()=>fs.watchFile('/dsh-home'),{code:'E_DSH_WATCHFILE_UNAVAILABLE'});
const two=fs.watch('/dsh-home'),three=fs.watch('/dsh-home');assert.throws(()=>fs.watch('/dsh-home'),{code:'E_DSH_WATCH_COUNT_BOUND'});two.close();three.close();
const closing=api.watch('/dsh-home'),last=closing.next();controller.abort();assert.deepEqual(await last,{done:true});assert(watcher.closed);assert.throws(()=>fs.watch('/dsh-home'),{code:'E_DSH_WATCH_REVOKED'});
store.close();process.stdout.write('VIRTUAL_WATCH_EVENT_ABORT_QUOTA_AND_OWNER_REVOCATION=PASS_UNIT\n');
