// Flat bounded virtual namespace. No host path, link or native descriptor.
import path from 'node:path';
const error=code=>Object.assign(new Error(code),{code});
const owned=name=>name==='/dsh-home'||name.startsWith('/dsh-home/')||name==='/dsh-workspace'||name.startsWith('/dsh-workspace/');
function valid(name){return owned(name)&&Buffer.from(name).toString('utf8')===name&&Buffer.byteLength(name)<=4096&&!/[\\\x00-\x1f\x7f]/.test(name)&&name.split('/').length<=65&&name.split('/').slice(1).every(part=>part&&part!=='.'&&part!=='..'&&Buffer.byteLength(part)<=255);}
export function decodeSessionSnapshot(input){
 if(!Buffer.isBuffer(input)||input.length<12||input.length>20*1024*1024||input.subarray(0,8).toString('ascii')!=='DSHFS001')throw error('E_DSH_SNAPSHOT_VERSION');
 let offset=12,total=0;const count=input.readUInt32BE(8),entries=new Map(),decoder=new TextDecoder('utf-8',{fatal:true});
 if(count<2||count>4096)throw error('E_DSH_SNAPSHOT_COUNT');
 const need=n=>{if(n<0||n>input.length-offset)throw error('E_DSH_SNAPSHOT_TRUNCATED');};
 try{
  for(let i=0;i<count;i++){
   need(2);const n=input.readUInt16BE(offset);offset+=2;need(n+15);let name;
   try{name=decoder.decode(input.subarray(offset,offset+n));}catch{throw error('E_DSH_SNAPSHOT_UTF8');}offset+=n;
   if(!n||!valid(name)||entries.has(name))throw error('E_DSH_SNAPSHOT_PATH');
   const type=input[offset],mode=input.readUInt16BE(offset+1),time=input.readBigInt64BE(offset+3),size=input.readUInt32BE(offset+11);offset+=15;
   if(type>1||(mode&~0o700)||time<0n||time>BigInt(Number.MAX_SAFE_INTEGER)||size>8*1024*1024||(type===1&&size))throw error('E_DSH_SNAPSHOT_ENTRY');
   total+=size;if(total>16*1024*1024)throw error('E_DSH_SNAPSHOT_BOUND');need(size);
   entries.set(name,{directory:type===1,mode,mtime:Number(time),data:Buffer.from(input.subarray(offset,offset+size))});offset+=size;
  }
  if(offset!==input.length||!entries.get('/dsh-home')?.directory||!entries.get('/dsh-workspace')?.directory)throw error('E_DSH_SNAPSHOT_ROOTS');
  for(const name of entries.keys())if(path.dirname(name)!=='/'&&!entries.get(path.dirname(name))?.directory)throw error('E_DSH_SNAPSHOT_PARENT');
  return entries;
 }catch(cause){for(const row of entries.values())row.data.fill(0);throw cause;}
}
export function encodeSessionSnapshot(entries){
 const chunks=[],head=Buffer.alloc(12);head.write('DSHFS001');head.writeUInt32BE(entries.size,8);chunks.push(head);
 for(const [name,row] of entries){const encoded=Buffer.from(name),data=row.directory?Buffer.alloc(0):row.data;
  if(!valid(name)||!Buffer.isBuffer(data))throw error('E_DSH_SNAPSHOT_PATH');
  const meta=Buffer.alloc(17);meta.writeUInt16BE(encoded.length);meta[2]=row.directory?1:0;meta.writeUInt16BE(row.mode,3);meta.writeBigInt64BE(BigInt(row.mtime),5);meta.writeUInt32BE(data.length,13);
  chunks.push(meta.subarray(0,2),encoded,meta.subarray(2),data);
 }
 const bytes=Buffer.concat(chunks);try{const checked=decodeSessionSnapshot(bytes);for(const row of checked.values())row.data.fill(0);return bytes;}catch(cause){bytes.fill(0);throw cause;}
}
