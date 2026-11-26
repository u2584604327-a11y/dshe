// Synthetic storage/protocol peer only. No original main/Android/READY claim.
import http from 'node:http';
import {createHash} from 'node:crypto';
const {installProfileTransport}=await import(process.argv[2]);
const transport=await installProfileTransport();
const initial=await transport.filesystem.ready;
const first=Number(process.argv[3]);
if(initial.version!==BigInt(first))throw Error('TEST_VERSION_RESTORE');
function snapshot(version){
  const payload=Buffer.alloc(96*1024);for(let i=0;i<payload.length;i++)payload[i]=(i+version)&255;
  const rows=['/dsh-home','/dsh-workspace','/dsh-home/record'].map((path,index)=>{
    const name=Buffer.from(path),data=index===2?payload:Buffer.alloc(0),meta=Buffer.alloc(17);
    meta.writeUInt16BE(name.length);meta[2]=index===2?0:1;meta.writeUInt16BE(index===2?0o600:0o700,3);
    meta.writeBigInt64BE(1n,5);meta.writeUInt32BE(data.length,13);
    return Buffer.concat([meta.subarray(0,2),name,meta.subarray(2),data]);
  });
  const header=Buffer.alloc(12);header.write('DSHFS001');header.writeUInt32BE(3,8);return Buffer.concat([header,...rows]);
}
if(first&& !initial.bytes.equals(snapshot(first)))throw Error('TEST_BYTES_RESTORE');
initial.bytes.fill(0);
if(process.argv[4]==='COMMIT_NOW'){transport.filesystem.commit(snapshot(first+1));throw Error('TEST_MALICIOUS_ACK_ACCEPTED');}
let version=first;
const server=http.createServer((req,res)=>{
  if(req.url!=='/commit'){res.writeHead(404).end();return;}
  const bytes=snapshot(version+1);
  const next=transport.filesystem.commit(bytes);bytes.fill(0);
  if(next!==BigInt(version+1))throw Error('TEST_ACK_VERSION');version++;
  res.end(String(version));
});
server.listen(transport.requestedPort,'127.0.0.1');
process.on('SIGTERM',()=>process.exit(0)); // actual original-main shutdown has no FINISH frame
