// One reader owns fd0 and one writer owns fd1. Whole frames stay in this
// bounded queue until consumed: a synchronous filesystem ACK cannot be hidden
// in an outstanding async iterator. Original Node version/stdio are pinned.
import fs from 'node:fs';

export class ProfileWire {
  constructor(input,output) {
    this.input=input;this.output=output;this.parts=[];this.offset=0;this.length=0;this.waiters=[];this.closed=false;this.failure=null;
    this.read=fs.readSync.bind(fs);this.write=fs.writeSync.bind(fs);this.gate=new Int32Array(new SharedArrayBuffer(4));
    if(input.fd!==0||output.fd!==1||input.readableLength||!fs.fstatSync(0).isFIFO()||!fs.fstatSync(1).isFIFO()||
       typeof input._handle?.setBlocking!=='function'||typeof output._handle?.setBlocking!=='function')throw this.error('E_DSH_PROFILE_STDIO');
    input.pause();
    if(input._handle.setBlocking(false)!==0||output._handle.setBlocking(false)!==0)throw this.error('E_DSH_PROFILE_NONBLOCKING');
    this.poll=()=>{if(this.closed)return;try{this.drain();}catch(error){this.stop(error);return;}if(!this.closed)this.timer=setTimeout(this.poll,2);};
    this.poll();
  }
  error(code){return Object.assign(new Error(code),{code});}
  wake(){for(const waiter of this.waiters.splice(0))this.failure?waiter.reject(this.failure):waiter.resolve();}
  drain(){
    for(let round=0;round<16&&this.length<2*1024*1024;round++){
      const block=Buffer.allocUnsafe(Math.min(65536,2*1024*1024-this.length));let count;
      try{count=this.read(0,block,0,block.length,null);}catch(error){if(error.code==='EINTR')continue;if(error.code==='EAGAIN'||error.code==='EWOULDBLOCK')break;throw error;}
      if(count===0){this.stop(this.error('E_DSH_PROFILE_EOF'));return;}
      this.parts.push(block.subarray(0,count));this.length+=count;
    }
    if(this.length)this.wake();
  }
  peek(length){
    if(length>this.length)throw this.error('E_DSH_PROFILE_INTERNAL_READ');
    if(this.parts[0]?.length-this.offset>=length)return this.parts[0].subarray(this.offset,this.offset+length);
    const result=Buffer.allocUnsafe(length);let used=0;
    for(let index=0;used<length;index++){const part=this.parts[index],offset=index===0?this.offset:0,n=Math.min(part.length-offset,length-used);part.copy(result,used,offset,offset+n);used+=n;}
    return result;
  }
  pop(length){const result=Buffer.from(this.peek(length));this.length-=length;
    while(length){const n=Math.min(length,this.parts[0].length-this.offset);this.offset+=n;length-=n;if(this.offset===this.parts[0].length){this.parts.shift();this.offset=0;}}
    return result;
  }
  async available(length){while(this.length<length){if(this.failure)throw this.failure;await new Promise((resolve,reject)=>this.waiters.push({resolve,reject}));}}
  async take(length){await this.available(length);return this.pop(length);}
  packetLength(){if(this.length<53)return null;const header=this.peek(53),length=header.readUInt32BE(17);
    if(header.subarray(0,4).toString('ascii')!=='DHF1'||length>16384)throw this.error('E_DSH_IPC_FRAME');return 53+length;
  }
  async packet(){for(;;){const length=this.packetLength();if(length!==null&&this.length>=length)return this.pop(length);await this.available(length??53);}}
  packetSync(deadline){
    for(;;){const length=this.packetLength();if(length!==null&&this.length>=length)return this.pop(length);
      if(this.failure)throw this.failure;if(process.hrtime.bigint()>=deadline)throw this.error('E_DSH_PROFILE_ACK_TIMEOUT');
      this.drain();if(this.failure&&this.length<(length??53))throw this.failure;
      if(this.length<(length??53))Atomics.wait(this.gate,0,0,2);
    }
  }
  writeFrame(frame,deadline=process.hrtime.bigint()+8_000_000_000n){
    let offset=0;while(offset<frame.length){
      if(this.failure)throw this.failure;if(process.hrtime.bigint()>=deadline)throw this.error('E_DSH_PROFILE_WRITE_TIMEOUT');
      try{const count=this.write(1,frame,offset,frame.length-offset);if(count<=0)throw this.error('E_DSH_PROFILE_WRITE_ZERO');offset+=count;}
      catch(error){if(error.code==='EINTR')continue;if(error.code!=='EAGAIN'&&error.code!=='EWOULDBLOCK')throw error;Atomics.wait(this.gate,0,0,2);}
    }
  }
  stop(failure){if(this.closed)return;this.closed=true;this.failure=failure??this.error('E_DSH_PROFILE_CLOSED');clearTimeout(this.timer);this.wake();}
}
