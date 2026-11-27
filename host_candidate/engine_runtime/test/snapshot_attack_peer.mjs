// Authenticated adversary for snapshot-specific host denials, never production.
import {createHmac,createHash} from 'node:crypto';
import {ProfileWire} from '../profile_wire.mjs';
const wire=new ProfileWire(process.stdin,process.stdout),hello=await wire.take(88);
const key=hello.subarray(8,40),session=hello.subarray(40,72),epoch=hello.subarray(72,80),mode=process.argv[2];
let seq=0n;
function send(type,id,data=Buffer.alloc(0)){
 const header=Buffer.alloc(21);header.write('DHF1');header[4]=type;header.writeBigUInt64BE(++seq,5);header.writeUInt32BE(id,13);header.writeUInt32BE(data.length,17);
 const tag=createHmac('sha256',key).update('N').update(session).update(epoch).update(header).update(data).digest();
 wire.writeFrame(Buffer.concat([header,tag,data]));
}
if(mode!=='UNGRANTED'){while((await wire.packet())[4]!==13){}}
const rows=['/dsh-home','/dsh-workspace',mode==='PATH'?'/data/private':'/dsh-home/record'].map((p,index)=>{
 const name=Buffer.from(p),meta=Buffer.alloc(17);meta.writeUInt16BE(name.length);meta[2]=index===2?0:1;meta.writeUInt16BE(index===2?0o600:0o700,3);meta.writeBigInt64BE(1n,5);return Buffer.concat([meta.subarray(0,2),name,meta.subarray(2)]);
});
const header=Buffer.alloc(12);header.write('DSHFS001');header.writeUInt32BE(3,8);const bytes=Buffer.concat([header,...rows]);
const meta=Buffer.alloc(44);meta.writeBigInt64BE(mode==='STALE'?77n:0n);meta.writeUInt32BE(bytes.length,8);createHash('sha256').update(bytes).digest().copy(meta,12);if(mode==='HASH')meta[12]^=1;
send(26,1,meta);
if(mode==='REPLAY'){send(26,1,meta);}
else if(mode==='OVERRUN'){send(27,1,Buffer.alloc(bytes.length+1));}
else{send(27,1,mode==='TRUNCATED'?bytes.subarray(1):bytes);send(28,1);}
setInterval(()=>{},1000);
