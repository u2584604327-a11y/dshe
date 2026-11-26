// Bounded owner namespace. Durable mode requires an explicit authenticated
// snapshot capability; this module cannot obtain one or authorize a launcher.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
import {decodeSessionSnapshot,encodeSessionSnapshot} from './session_snapshot.mjs';

let installed=false;
export function installSessionFilesystem({files, directories, privateFiles, resolve, notify=()=>{},
                                         maxBytes=16*1024*1024, maxEntries=4096, snapshotCapability}) {
  if(installed)throw Object.assign(new Error('E_DSH_SESSION_FS_ALREADY_INSTALLED'),{code:'E_DSH_SESSION_FS_ALREADY_INSTALLED'});
  if (!(files instanceof Map) || !(directories instanceof Set) || !(privateFiles instanceof Map) || typeof resolve!=='function') throw Error('E_DSH_SESSION_FS_INPUT');
  if(!Number.isInteger(maxBytes)||maxBytes<0||maxBytes>16*1024*1024||!Number.isInteger(maxEntries)||maxEntries<2||maxEntries>4096)throw Error('E_DSH_SESSION_FS_QUOTA');
  let closed=false, clock=Date.now(), sequence=0;
  const metadata=new Map(),handles=new Map();let handleSequence=0,activeHandle=null,transactionActive=false,events=[];
  let version=0n;const durable=snapshotCapability!==undefined;
  if(durable&&(typeof snapshotCapability?.commit!=='function'||typeof snapshotCapability?.version!=='bigint'||snapshotCapability.version<0n))throw Error('E_DSH_SNAPSHOT_CAPABILITY');
  const baseStat=fs.statSync, baseAccess=fs.accessSync,baseRead=fs.readFileSync,baseReaddir=fs.readdirSync,baseRealpath=fs.realpathSync;
  const error=code=>Object.assign(new Error(code),{code});
  const alive=()=>{if(closed)throw error('E_DSH_SESSION_FS_REVOKED');};
  const owned=name=>name==='/dsh-home'||name.startsWith('/dsh-home/')||name==='/dsh-workspace'||name.startsWith('/dsh-workspace/');
  const canonical=value=>{alive();if(Buffer.isBuffer(value)&&!Buffer.from(value.toString('utf8')).equals(value))throw error('EILSEQ');const name=resolve(value);if(Buffer.from(name).toString('utf8')!==name)throw error('EILSEQ');if(name!=='/'&&(Buffer.byteLength(name)>4096||/[\\\x00-\x1f\x7f]/.test(name)||name.split('/').length>65||name.split('/').slice(1).some(p=>!p||p==='.'||p==='..'||Buffer.byteLength(p)>255)))throw error('EINVAL');for(let parent=path.dirname(name);owned(parent);parent=path.dirname(parent))if(directories.has(parent)&&!(meta(parent,true).mode&0o100))throw error('EACCES');return name;};
  const writable=value=>{const name=canonical(value);if(!owned(name)||files.has(name))throw error('EROFS');for(const handle of handles.values())if(handle.name===name&&handle!==activeHandle)throw error('EBUSY');return name;};
  const root=name=>name==='/dsh-home'||name==='/dsh-workspace';
  const tick=()=>clock=Math.max(Date.now(),clock+1);
  const mode=(requested,directory)=>{const value=typeof requested==='string'&&/^[0-7]+$/.test(requested)?parseInt(requested,8):requested??(directory?0o700:0o600);if(!Number.isInteger(value)||value<0||value>0o7777)throw error('EINVAL');return value&0o700;};
  const meta=(name,directory)=>{let row=metadata.get(name);if(!row){row={mode:directory?0o700:0o600,ino:++sequence,mtime:tick()};metadata.set(name,row);}return row;};
  const exists=name=>directories.has(name)||privateFiles.has(name)||files.has(name);
  const count=()=>privateFiles.size+[...directories].filter(owned).length;
  const bytes=()=>[...privateFiles.values()].reduce((sum,b)=>sum+b.length,0);
  const parent=name=>{const p=path.dirname(name);if(!directories.has(p))throw error('ENOENT');if(owned(p)&&(meta(p,true).mode&0o300)!==0o300)throw error('EACCES');};
  const notice=(type,name)=>{if(transactionActive)events.push([type,name]);else notify(type,name);};
  const changed=(type,name)=>{meta(name,directories.has(name)).mtime=tick();notice(type,name);};
  const children=name=>[...directories,...privateFiles.keys()].filter(p=>p!==name&&p.startsWith(name+'/'));
  function stat(filename,options){const name=canonical(filename);const value=baseStat(name,options);if(!value||!owned(name))return value;
    const m=meta(name,value.isDirectory()),number=n=>options?.bigint?BigInt(n):n;
    const result=Object.assign(Object.create(Object.getPrototypeOf(value)),value,
      {uid:number(process.getuid()),gid:number(process.getgid()),ino:number(m.ino),mode:number((value.isDirectory()?0o40000:0o100000)|m.mode),
       mtimeMs:number(m.mtime),ctimeMs:number(m.mtime),mtime:new Date(m.mtime),ctime:new Date(m.mtime)});
    if(options?.bigint){result.mtimeNs=BigInt(m.mtime)*1000000n;result.ctimeNs=result.mtimeNs;}return result;
  }
  function mkdir(filename,options){const name=writable(filename),recursive=typeof options==='object'&&!!options?.recursive;
    if(privateFiles.has(name))throw error('EEXIST');if(directories.has(name)){if(recursive)return;throw error('EEXIST');}
    if(!recursive)parent(name);
    const missing=[];for(let p=name;!directories.has(p);p=path.dirname(p)){if(!owned(p)||privateFiles.has(p)||files.has(p))throw error('ENOTDIR');missing.push(p);}
    if(count()+missing.length>maxEntries)throw error('ENOSPC');
    for(const p of missing.reverse()){parent(p);directories.add(p);meta(p,true).mode=mode(typeof options==='number'?options:options?.mode,true);changed('rename',p);}
    return recursive?missing[0]:undefined;
  }
  function writeFile(filename,data,options){const name=writable(filename);parent(name);if(directories.has(name))throw error('EISDIR');
    const flag=typeof options==='object'?options?.flag??'w':'w';if(!['w','wx','a','ax'].includes(flag))throw error('EINVAL');
    const present=privateFiles.has(name);if(flag.endsWith('x')&&present)throw error('EEXIST');
    if(present&&!(meta(name,false).mode&0o200))throw error('EACCES');
    const encoding=typeof options==='string'?options:options?.encoding;
    const value=typeof data==='string'?Buffer.from(data,encoding):Buffer.from(data);
    const old=privateFiles.get(name),size=value.length+(flag[0]==='a'?(old?.length??0):0);
    if(size>8*1024*1024||bytes()+size-(old?.length??0)>maxBytes||(!present&&count()>=maxEntries))throw error('ENOSPC');
    const next=flag[0]==='a'&&old?Buffer.concat([old,value]):value;
    privateFiles.set(name,next);if(old)old.fill(0);if(!present)meta(name,false).mode=mode(typeof options==='object'?options?.mode:undefined,false);
    changed(present?'change':'rename',name);
  }
  function unlink(filename){const name=writable(filename);parent(name);if(directories.has(name))throw error('EISDIR');if(!privateFiles.has(name))throw error('ENOENT');
    privateFiles.get(name).fill(0);privateFiles.delete(name);metadata.delete(name);notice('rename',name);
  }
  function rm(filename,options={}){const name=writable(filename);if(root(name))throw error('EBUSY');
    if(!exists(name)){if(options.force)return;throw error('ENOENT');}parent(name);
    if(privateFiles.has(name))return unlink(name);
    const nested=children(name);if(!options.recursive){if(nested.length)throw error('ENOTEMPTY');throw error('EISDIR');}
    for(const item of nested){writable(item);parent(item);}
    for(const item of nested.filter(item=>privateFiles.has(item)))unlink(item);
    for(const item of nested.filter(item=>directories.has(item)).sort((a,b)=>b.length-a.length)){directories.delete(item);metadata.delete(item);notice('rename',item);}
    directories.delete(name);metadata.delete(name);notice('rename',name);
  }
  function rmdir(filename,options={}){const name=writable(filename);if(!directories.has(name))throw error(privateFiles.has(name)?'ENOTDIR':'ENOENT');
    if(root(name))throw error('EBUSY');parent(name);if(options.recursive)return rm(name,{recursive:true});if(children(name).length)throw error('ENOTEMPTY');
    directories.delete(name);metadata.delete(name);notice('rename',name);
  }
  function rename(from,to){const source=writable(from),target=writable(to);if(root(source)||root(target))throw error('EBUSY');
    if(!exists(source))throw error('ENOENT');if(source===target)return;parent(source);parent(target);if(target.startsWith(source+'/'))throw error('EINVAL');
    const dir=directories.has(source),targetDir=directories.has(target);
    if(exists(target)){if(dir!==targetDir)throw error(dir?'ENOTDIR':'EISDIR');if(targetDir&&children(target).length)throw error('ENOTEMPTY');}
    const moved=dir?[source,...children(source)]:[source];
    const plan=moved.map(old=>[old,target+old.slice(source.length),directories.has(old),privateFiles.get(old),metadata.get(old)]);
    for(const old of moved)writable(old);
    // All validation precedes the same-turn commit. There are no symlinks,
    // external processes or host filesystem operations in this namespace.
    if(privateFiles.has(target)){privateFiles.get(target).fill(0);privateFiles.delete(target);}directories.delete(target);metadata.delete(target);
    for(const [old] of plan){directories.delete(old);privateFiles.delete(old);metadata.delete(old);}
    for(const [old,next,isDir,data,m] of plan){if(isDir)directories.add(next);else privateFiles.set(next,data);if(m)metadata.set(next,m);notice('rename',old);changed('rename',next);}
  }
  function chmod(filename,bits){const name=writable(filename);if(!exists(name))throw error('ENOENT');meta(name,directories.has(name)).mode=mode(bits,directories.has(name));changed('change',name);}
  function mkdtemp(prefix,options){const base=writable(prefix);parent(base);if(count()>=maxEntries)throw error('ENOSPC');
    let name;do{name=base+randomBytes(6).toString('hex');}while(exists(name));mkdir(name,{mode:0o700});
    const encoding=typeof options==='string'?options:options?.encoding;return encoding==='buffer'?Buffer.from(name):name;
  }
  function access(filename,flags=fs.constants.F_OK){const name=canonical(filename);if(!owned(name))return baseAccess(name,flags);
    const value=stat(name);if(((flags&fs.constants.R_OK)&&!(value.mode&0o400))||((flags&fs.constants.W_OK)&&!(value.mode&0o200)))throw error('EACCES');if((flags&fs.constants.X_OK)&&!(value.mode&0o100))throw error('EACCES');
  }
  function encoded(){const entries=new Map();for(const name of [...directories].filter(owned).sort()){const row=meta(name,true);entries.set(name,{directory:true,mode:row.mode,mtime:row.mtime});}
    for(const [name,data] of [...privateFiles].sort(([a],[b])=>a.localeCompare(b))){const row=meta(name,false);entries.set(name,{directory:false,mode:row.mode,mtime:row.mtime,data});}return encodeSessionSnapshot(entries);
  }
  function restore(entries){for(const value of privateFiles.values())value.fill(0);privateFiles.clear();for(const name of [...directories])if(owned(name))directories.delete(name);metadata.clear();
    for(const [name,row] of entries){if(row.directory)directories.add(name);else privateFiles.set(name,row.data);metadata.set(name,{mode:row.mode,mtime:row.mtime,ino:++sequence});clock=Math.max(clock,row.mtime);}
  }
  if(durable){const initial=decodeSessionSnapshot(snapshotCapability.bytes);restore(initial);version=snapshotCapability.version;}
  function flush(){if(!durable)throw error('E_DSH_DURABLE_STORE_UNAVAILABLE');const payload=encoded();try{const next=snapshotCapability.commit(payload);if(next!==version+1n)throw error('E_DSH_STORE_ACK_VERSION');version=next;}finally{payload.fill(0);}}
  function mutate(operation,...args){alive();if(transactionActive)return operation(...args);
    const previous=new Map([...privateFiles].map(([name,data])=>[name,Buffer.from(data)])),oldDirs=[...directories].filter(owned),oldMeta=new Map([...metadata].map(([name,row])=>[name,{...row}]));
    transactionActive=true;events=[];let value,committing=false;
    try{value=operation(...args);if(durable){committing=true;flush();}}
    catch(cause){for(const data of privateFiles.values())data.fill(0);privateFiles.clear();for(const [name,data] of previous)privateFiles.set(name,data);for(const name of [...directories])if(owned(name))directories.delete(name);for(const name of oldDirs)directories.add(name);metadata.clear();for(const [name,row] of oldMeta)metadata.set(name,row);events=[];
      if(committing)close();throw cause;
    }finally{transactionActive=false;}
    for(const data of previous.values())data.fill(0);const deliver=events;events=[];for(const event of deliver)notify(...event);return value;
  }
  function close(){if(closed)return;closed=true;for(const handle of handles.values())handle.closed=true;handles.clear();for(const value of privateFiles.values())value.fill(0);privateFiles.clear();for(const name of [...directories])if(owned(name))directories.delete(name);metadata.clear();}
  async function open(filename,flag='r',bits=0o600){alive();const name=canonical(filename);if(!owned(name))throw error('EROFS');
    if(!['r','w','wx','a','ax'].includes(flag))throw error('E_DSH_OPEN_FLAGS_UNAVAILABLE');if(handles.size>=64||handleSequence>=0x3ffffffe)throw error('EMFILE');
    if(flag==='r'){stat(name);access(name,fs.constants.R_OK);}else mutate(writeFileOperation,name,Buffer.alloc(0),{flag,mode:bits});
    const handle={name,closed:false},directory=directories.has(name);let position=0;const id=0x40000000+(++handleSequence);if(id>=0x7fffffff)throw error('EMFILE');handles.set(id,handle);
    const valid=()=>{alive();if(handle.closed)throw error('EBADF');};
    const perform=(operation,...args)=>{valid();if(flag==='r')throw error('EBADF');if(directory)throw error('EISDIR');activeHandle=handle;try{return mutate(operation,...args);}finally{activeHandle=null;}};
    async function writeHandleFile(data,options){const bytes=typeof data==='string'?Buffer.from(data,typeof options==='string'?options:options?.encoding):Buffer.from(data);valid();const old=privateFiles.get(name);if(!old)throw error('ENOENT');const offset=flag[0]==='a'?old.length:position;
      if(offset+bytes.length>8*1024*1024)throw error('ENOSPC');const next=Buffer.alloc(Math.max(old.length,offset+bytes.length));old.copy(next);bytes.copy(next,offset);try{perform(writeFilePath,name,next,{flag:'w'});position=offset+bytes.length;}finally{next.fill(0);bytes.fill(0);}
    }
    // The public promise handle supports the original atomic JSON publish path.
    // Native fd interoperability, streams and unsupported inode operations deny.
    const writeFilePath=writeFileOperation;
    return Object.freeze({fd:id,
      async writeFile(data,options){return writeHandleFile(data,options);},
      async readFile(options){valid();if(directory)throw error('EISDIR');if(flag!=='r')throw error('EBADF');const data=privateFiles.get(name);if(!data)throw error('ENOENT');const remaining=Buffer.from(data.subarray(position));position=data.length;const encoding=typeof options==='string'?options:options?.encoding;return encoding?remaining.toString(encoding):remaining;},
      async stat(options){valid();return stat(name,options);},
      async sync(){valid();try{flush();}catch(cause){if(durable)close();throw cause;}},async datasync(){valid();try{flush();}catch(cause){if(durable)close();throw cause;}},
      async close(){if(handle.closed)return;handle.closed=true;handles.delete(id);},
      createReadStream(){valid();throw error('E_DSH_FH_STREAM_UNAVAILABLE');},createWriteStream(){valid();throw error('E_DSH_FH_STREAM_UNAVAILABLE');},
      async [Symbol.asyncDispose](){handle.closed=true;handles.delete(id);},
    });
  }
  const writeFileOperation=writeFile;
  const callback=fn=>(...args)=>{const done=args.pop();if(typeof done!=='function')throw error('ERR_INVALID_ARG_TYPE');queueMicrotask(()=>{let value;try{value=fn(...args);}catch(e){done(e);return;}done(null,value);});};
  const operations={mkdir,writeFile,appendFile:(file,data,options)=>writeFile(file,data,{...(typeof options==='object'?options:{encoding:options}),flag:typeof options==='object'?options.flag??'a':'a'}),unlink,rm,rmdir,rename,chmod,mkdtemp};
  for(const [name,operation] of Object.entries(operations)){const fn=(...args)=>mutate(operation,...args);fs[name+'Sync']=fn;fs[name]=callback(fn);fs.promises[name]=async(...args)=>fn(...args);}
  const readers={stat,lstat:stat,access,
    readFile:(file,options)=>{const name=canonical(file);if(owned(name))access(name,fs.constants.R_OK);return baseRead(name,options);},
    readdir:(file,options)=>{const name=canonical(file);if(owned(name))access(name,fs.constants.R_OK);return baseReaddir(name,options);},
    realpath:(file,options)=>{const name=canonical(file);stat(name);return baseRealpath(name,options);}};
  for(const [name,fn] of Object.entries(readers)){fs[name+'Sync']=fn;fs[name]=callback(fn);fs.promises[name]=async(...args)=>fn(...args);}
  fs.realpathSync.native=fs.realpathSync;fs.realpath.native=fs.realpath;
  fs.promises.open=open;fs.existsSync=filename=>{try{return !!stat(filename);}catch{return false;}};
  installed=true;syncBuiltinESMExports();
  return Object.freeze({durable,close});
}
