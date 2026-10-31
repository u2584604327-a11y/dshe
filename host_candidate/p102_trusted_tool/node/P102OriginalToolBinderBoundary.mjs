/**
 * P102 Node-side candidate for a single original ToolRuntime tool-call ->
 * trusted Android Binder result. This is NOT a production Android bridge.
 *
 * The host must supply BOTH: (1) a verified original live-turn/call validator,
 * and (2) a transport backed by the non-exported isolated worker / trusted
 * Android Messenger port. JS cannot attest Binder sendingUid or UI approval.
 * The transport must NOT be exposed to model, web page or plugin code.
 *
 * This class neither registers tools nor appends Session/tool/result events.
 * Original ToolRuntime must own those operations after integration.
 */
export class P102OriginalToolBinderBoundary {
  #transport;
  #assertOriginalCall;
  #deadlineMs;
  #state='NEW';
  #cancelled=false;

  constructor({transport,assertOriginalCall,deadlineMs=10000}={}) {
    if(!transport || typeof transport.bind!=='function' ||
       typeof transport.request!=='function' ||
       typeof assertOriginalCall!=='function' ||
       !Number.isSafeInteger(deadlineMs) || deadlineMs<1 || deadlineMs>10000)
      throw Error('P102_TRUSTED_ORIGINAL_AND_NATIVE_PORT_REQUIRED');
    this.#transport=transport;
    this.#assertOriginalCall=assertOriginalCall;
    this.#deadlineMs=deadlineMs;
  }

  get state(){return this.#state;}
  revoke(){
    this.#cancelled=true;
    if(this.#state!=='COMPLETED')this.#state='REVOKED';
    // Transport cancellation is advisory; it cannot re-arm this slot.
    try{this.#transport.revoke?.();}catch{}
  }

  /**
   * callId MUST be the original ToolRuntime tool-call ID, not a new broker ID.
   * sessionId MUST come from the original SessionStore-backed AgentLoop.
   * Host Android session is separately minted by the native Binder HELLO.
   * Returns a value only; original ToolRuntime owns result archival.
   */
  async execute({sessionId,callId,toolName,args}={}) {
    if(this.#state!=='NEW')throw Error('P102_REPLAY_OR_CONCURRENT_CALL_DENIED');
    this.#state='IN_FLIGHT'; // claim the one-shot slot before any await
    if(typeof sessionId!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)||
       typeof callId!=='string'||!/^[A-Za-z0-9_-]{1,96}$/.test(callId)||
       toolName!=='read_synthetic_fixture'||
       args===null||typeof args!=='object'||Array.isArray(args)||
       Object.keys(args).length!==1||args.query!=='fixture'){
      this.#state='REJECTED';
      throw Error('P102_NONCANONICAL_ORIGINAL_TOOL_CALL_DENIED');
    }
    const originalCall=Object.freeze({sessionId,callId,toolName});
    const canonicalArgs='{"query":"fixture"}';
    let timer;
    try{
      const run=(async()=>{
        if(await this.#assertOriginalCall(originalCall)!==true)
          throw Error('P102_ORIGINAL_TURN_NOT_VERIFIED');
        if(this.#cancelled)throw Error('P102_REVOKED');
        const binding=await this.#transport.bind();
        if(this.#cancelled)throw Error('P102_REVOKED');
        if(!binding||typeof binding.session!=='string'||
           !/^[a-f0-9]{64}$/.test(binding.session))
          throw Error('P102_NATIVE_HOST_SESSION_INVALID');
        const request=Object.freeze({
          session:binding.session,callId,toolName,arguments:canonicalArgs
        });
        const terminal=await this.#transport.request(request);
        if(this.#cancelled)throw Error('P102_REVOKED');
        if(!terminal||typeof terminal!=='object'||Array.isArray(terminal)||
           terminal.callId!==callId||
           terminal.outcomeUnknown!==false||terminal.retrySafe!==false||
           terminal.status!=='SUCCESS'||
           terminal.fixedResult!=='fixture-read-success'||
           Object.keys(terminal).sort().join(',')!==
             'callId,fixedResult,outcomeUnknown,retrySafe,status')
          throw Error('P102_NATIVE_TERMINAL_UNVERIFIED');
        // Revalidate original live turn after asynchronous native approval.
        if(await this.#assertOriginalCall(originalCall)!==true)
          throw Error('P102_ORIGINAL_TURN_STALE_AFTER_NATIVE');
        if(this.#cancelled)throw Error('P102_REVOKED');
        return Object.freeze({value:'fixture-read-success'});
      })();
      const timeout=new Promise((_,reject)=>{
        timer=setTimeout(()=>reject(Error('P102_NATIVE_RESULT_TIMEOUT_UNKNOWN_OUTCOME')),
                         this.#deadlineMs);
      });
      const result=await Promise.race([run,timeout]);
      if(this.#cancelled)throw Error('P102_REVOKED');
      this.#state='COMPLETED';
      return result;
    }catch(error){
      if(!this.#cancelled)this.#state='BLOCKED_NO_RETRY';
      throw error;
    }finally{
      clearTimeout(timer);
      if(this.#state!=='COMPLETED'){
        try{this.#transport.revoke?.();}catch{}
      }
    }
  }
}
