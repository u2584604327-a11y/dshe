// Adversarial authenticated child, only for protocol rejection tests.
import {createHmac} from 'node:crypto';
import fs from 'node:fs';
const iterator=process.stdin[Symbol.asyncIterator]();let pending=Buffer.alloc(0);
async function take(n){while(pending.length<n){const r=await iterator.next();if(r.done)throw Error('EOF');pending=Buffer.concat([pending,r.value]);}const value=pending.subarray(0,n);pending=pending.subarray(n);return value;}
const hello=await take(88), key=hello.subarray(8,40),session=hello.subarray(40,72),epoch=hello.subarray(72,80);
const port=hello.readUInt32BE(84),mode=process.argv[2];
if(mode==='EOF_EXIT'){await new Promise(resolve=>setTimeout(resolve,100));process.exit(7);}
if(mode==='EOF_BLOCKED'){fs.closeSync(1);setInterval(()=>{},1000);await new Promise(()=>{});}
if(mode==='EOF_ALIVE'){fs.closeSync(1);setInterval(()=>{},1000);for await(const ignored of iterator){};await new Promise(()=>{});}
function frame(type,id,seq,data=Buffer.alloc(0),length=data.length){
 const h=Buffer.alloc(21);h.write('DHF1');h[4]=type;h.writeBigUInt64BE(BigInt(seq),5);h.writeUInt32BE(id,13);h.writeUInt32BE(length,17);
 const tag=createHmac('sha256',key).update('N').update(mode==='OLD_SESSION'?Buffer.alloc(32):session).update(epoch).update(h).update(data).digest();
 if(mode==='BAD_MAC')tag[0]^=1;return Buffer.concat([h,tag,data]);
}
const portData=Buffer.alloc(4);portData.writeUInt32BE(port);
if(mode==='OVERSIZE')process.stdout.write(frame(16,0,1,Buffer.alloc(0),16385));
else if(mode==='UNSOLICITED')process.stdout.write(frame(17,1,1,Buffer.from('x')));
else{
 const first=frame(16,0,1,portData);process.stdout.write(first);
 if(mode==='REPLAY')process.stdout.write(first);
 if(mode==='DUP_LISTEN')process.stdout.write(frame(16,0,2,portData));
 if(mode==='CREDIT')process.stdout.write(frame(24,0,2,Buffer.from([0,0,0,1])));
 if(mode==='RESERVED_CREDIT'){
   const header=await take(53),size=header.readUInt32BE(17);await take(size);
   process.stdout.write(frame(20,header.readUInt32BE(13),2,Buffer.from([0,0,0,1])));
 }
}
for await(const ignored of iterator){} // remain alive until the host revokes
