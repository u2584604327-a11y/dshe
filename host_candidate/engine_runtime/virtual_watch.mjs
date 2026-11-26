// Watch only the verified virtual namespace. No native directory/FD fallback.
import fs from 'node:fs';
import path from 'node:path';
import {EventEmitter} from 'node:events';
import {syncBuiltinESMExports} from 'node:module';

let installed=false;
export function installVirtualWatchers({resolve,stat,signal,maxWatchers=2048}) {
  if(installed)throw Object.assign(new Error('E_DSH_WATCH_ALREADY_INSTALLED'),{code:'E_DSH_WATCH_ALREADY_INSTALLED'});
  if(typeof resolve!=='function'||typeof stat!=='function'||!signal||typeof signal.addEventListener!=='function')throw Error('E_DSH_WATCH_OWNER');
  const watchers=new Set();let closed=false;
  const error=code=>Object.assign(new Error(code),{code});
  const alive=()=>{if(closed||signal.aborted)throw error('E_DSH_WATCH_REVOKED');};
  class Watcher extends EventEmitter {
    constructor(filename,options,listener){super();this.filename=filename;this.directory=stat(filename).isDirectory();this.options=options;this.closed=false;this.pending=0;
      this.keepAlive=setInterval(()=>{},2**30);if(options.persistent===false)this.keepAlive.unref();
      if(listener)this.on('change',listener);watchers.add(this);
      if(options.signal){this.cancel=()=>this.close();options.signal.addEventListener('abort',this.cancel,{once:true});if(options.signal.aborted)this.close();}
    }
    close(){if(this.closed)return;this.closed=true;watchers.delete(this);clearInterval(this.keepAlive);this.options.signal?.removeEventListener('abort',this.cancel);queueMicrotask(()=>this.emit('close'));}
    ref(){if(!this.closed)this.keepAlive.ref();return this;}
    unref(){this.keepAlive.unref();return this;}
    deliver(type,filename){if(this.closed)return;
      const relative=path.relative(this.filename,filename);
      if(filename!==this.filename&&(!this.directory||relative==='..'||relative.startsWith('../')||(!this.options.recursive&&relative.includes('/'))))return;
      if(++this.pending>64){this.close();this.emit('error',error('E_DSH_WATCH_EVENT_BOUND'));return;}
      const name=filename===this.filename?path.basename(filename):relative;
      queueMicrotask(()=>{this.pending--;if(!this.closed)this.emit('change',type,this.options.encoding==='buffer'?Buffer.from(name):name);});
    }
  }
  fs.watch=(filename,options,listener)=>{
    alive();const name=resolve(filename);
    if(typeof options==='function'){listener=options;options={};}else if(typeof options==='string')options={encoding:options};
    options=options??{};if(options.signal&&(!(options.signal instanceof AbortSignal)))throw error('ERR_INVALID_ARG_TYPE');if(listener!==undefined&&typeof listener!=='function')throw error('ERR_INVALID_ARG_TYPE');
    if(options.encoding!==undefined&&options.encoding!=='utf8'&&options.encoding!=='utf-8'&&options.encoding!=='buffer')throw error('ERR_INVALID_ARG_VALUE');
    if(watchers.size>=maxWatchers)throw error('E_DSH_WATCH_COUNT_BOUND');
    return new Watcher(name,{...options},listener);
  };
  // Native stat-polling would observe the host rather than the virtual tree.
  // It is not silently enabled until its virtual semantics are implemented.
  fs.watchFile=filename=>{alive();resolve(filename);throw error('E_DSH_WATCHFILE_UNAVAILABLE');};
  fs.unwatchFile=filename=>{alive();resolve(filename);};
  fs.promises.watch=(filename,options={})=>{
    const queue=[],pending=[];let done=false,failure;
    const watcher=fs.watch(filename,options,(eventType,filename)=>{
      if(pending.length)pending.shift().resolve({value:{eventType,filename},done:false});
      else if(queue.length<64)queue.push({eventType,filename});
      else{failure=error('E_DSH_WATCH_EVENT_BOUND');watcher.close();}
    });
    watcher.on('error',cause=>{failure=cause;watcher.close();});
    const finish=()=>{done=true;queue.length=0;options.signal?.removeEventListener('abort',abort);for(const waiter of pending.splice(0))failure?waiter.reject(failure):waiter.resolve({done:true});};
    const abort=()=>{failure=Object.assign(error('ABORT_ERR'),{name:'AbortError'});watcher.close();finish();};
    watcher.on('close',finish);
    if(options.signal){options.signal.addEventListener('abort',abort,{once:true});if(options.signal.aborted)abort();}
    if(watcher.closed&&!failure)done=true;
    return {[Symbol.asyncIterator](){return this;},next(){if(failure)return Promise.reject(failure);if(queue.length)return Promise.resolve({value:queue.shift(),done:false});if(done)return Promise.resolve({done:true});return new Promise((resolve,reject)=>pending.push({resolve,reject}));},
      return(){queue.length=0;watcher.close();return Promise.resolve({done:true});}};
  };
  const close=()=>{if(closed)return;closed=true;for(const watcher of [...watchers])watcher.close();signal.removeEventListener('abort',close);};
  signal.addEventListener('abort',close,{once:true});if(signal.aborted)close();
  installed=true;syncBuiltinESMExports();
  return Object.freeze({close,notify(type,filename){alive();if(type!=='change'&&type!=='rename')throw error('EINVAL');const name=resolve(filename);for(const watcher of [...watchers])watcher.deliver(type,name);}});
}
