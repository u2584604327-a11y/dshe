// Inserted inside the reviewed HTTP transport. These frames carry private
// snapshots; they never pass through stdout/stderr LogSink or an HTTP route.
const PF={INIT_BEGIN:11,INIT_DATA:12,INIT_END:13,ACK:14,BEGIN:26,DATA:27,COMMIT:28};
const storageReady=Promise.withResolvers();storageReady.promise.catch(()=>{});
let storageVersion=0n,storageInitialized=false,storageIncoming=null,storageOffset=0,storageDigest;
let transactionId=0,transactionActive=false,transactionAck=null,profileDeadline;
const profileInitTimer=setTimeout(()=>{if(!storageInitialized)fail(error('E_DSH_STORE_INIT_TIMEOUT'));},15000);
const deferred=[];let deferredBytes=0,drainingDeferred=false;
function decodeProfileFrame(packet){
  const header=packet.subarray(0,21),signature=packet.subarray(21,53);
  if(header.length!==21||header.subarray(0,4).toString('ascii')!=='DHF1')throw error('E_DSH_IPC_FRAME');
  const type=header[4],seq=header.readBigUInt64BE(5),id=header.readUInt32BE(13),length=header.readUInt32BE(17);
  if(seq!==received+1n||seq>0x7fffffffffffffffn||length>CHUNK||id>0x7fffffff||packet.length!==53+length)throw error('E_DSH_IPC_FRAME');
  const data=packet.subarray(53);if(!timingSafeEqual(signature,tag('H',header,data)))throw error('E_DSH_IPC_AUTH');
  received=seq;return {type,id,length,data};
}
function acceptStorageFrame(frame){
  const {type,id,length,data}=frame;
  if(type===PF.INIT_BEGIN){
    if(storageInitialized||storageIncoming||id!==0||length!==44)throw error('E_DSH_STORE_INIT');
    const size=data.readUInt32BE(8);storageVersion=data.readBigUInt64BE(0);
    if(storageVersion>0x7fffffffffffffffn||size<12||size>20*1024*1024)throw error('E_DSH_STORE_INIT_BOUND');
    storageIncoming=Buffer.allocUnsafe(size);storageOffset=0;storageDigest=Buffer.from(data.subarray(12));return true;
  }
  if(type===PF.INIT_DATA){
    if(!storageIncoming||id!==0||!length||length>storageIncoming.length-storageOffset)throw error('E_DSH_STORE_INIT_DATA');
    data.copy(storageIncoming,storageOffset);storageOffset+=length;return true;
  }
  if(type===PF.INIT_END){
    if(!storageIncoming||id!==0||length||storageOffset!==storageIncoming.length||
       !timingSafeEqual(storageDigest,createHash('sha256').update(storageIncoming).digest()))throw error('E_DSH_STORE_INIT_SEAL');
    storageInitialized=true;clearTimeout(profileInitTimer);const bytes=storageIncoming;storageIncoming=null;storageDigest.fill(0);
    storageReady.resolve({version:storageVersion,bytes});return true;
  }
  if(type===PF.ACK){
    if(!transactionActive||transactionAck||id!==transactionId||length!==9)throw error('E_DSH_STORE_ACK');
    const version=data.readBigUInt64BE(0),status=data[8];
    if(status!==0||version!==storageVersion+1n)throw error('E_DSH_STORE_COMMIT_REJECTED');
    transactionAck=version;return true;
  }
  return false;
}
function applyProfileFrame(frame){
  if(acceptStorageFrame(frame))return;
  // INSERT_ORIGINAL_HTTP_FRAME_ACTIONS
}
function drainDeferred(){
  if(drainingDeferred||closed)return;drainingDeferred=true;
  try{while(deferred.length&&!closed){const frame=deferred.shift();deferredBytes-=53+frame.length;applyProfileFrame(frame);}}
  catch(cause){fail(cause);}finally{drainingDeferred=false;}
}
function commitSnapshot(bytes){
  if(closed||!storageInitialized||transactionActive||!Buffer.isBuffer(bytes)||bytes.length<12||bytes.length>20*1024*1024||
      storageVersion===0x7fffffffffffffffn||transactionId===0x7fffffff)throw error('E_DSH_STORE_REQUEST');
  transactionActive=true;transactionAck=null;transactionId++;profileDeadline=process.hrtime.bigint()+15_000_000_000n;
  try{
    const meta=Buffer.alloc(44);meta.writeBigUInt64BE(storageVersion,0);meta.writeUInt32BE(bytes.length,8);createHash('sha256').update(bytes).digest().copy(meta,12);
    sendProfileSync(PF.BEGIN,transactionId,meta);
    for(let offset=0;offset<bytes.length;offset+=CHUNK)sendProfileSync(PF.DATA,transactionId,bytes.subarray(offset,Math.min(offset+CHUNK,bytes.length)));
    sendProfileSync(PF.COMMIT,transactionId,empty);
    while(transactionAck===null){
      const frame=decodeProfileFrame(source.packetSync(profileDeadline));
      if(acceptStorageFrame(frame))continue;
      // Finish this authenticated commit before delivering graceful shutdown.
      // The host's independent stop deadline still forcibly revokes a stall.
      if(deferredBytes+53+frame.length>2*1024*1024)throw error('E_DSH_STORE_DEFERRED_BOUND');
      deferred.push(frame);deferredBytes+=53+frame.length;
    }
    storageVersion=transactionAck;return storageVersion;
  }catch(cause){fail(cause);throw cause;}
  finally{transactionActive=false;profileDeadline=undefined;queueMicrotask(drainDeferred);}
}
const reading=(async()=>{
  for(;;){const frame=decodeProfileFrame(await source.packet());applyProfileFrame(frame);}
})().catch(cause=>{if(!normalStop)fail(cause);});
