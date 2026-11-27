/**
 * P113: read-only pending call observation in the ACTUAL original ToolRuntime
 * execution path, for the isolated existing P101 original AgentLoop roundtrip.
 *
 * This is original Node-owned in-process provenance evidence ONLY.
 * It is NOT Android-native independent attestation, nor an authorization
 * token, nor a protection against arbitrary malicious Node/JS code.
 * It does not call tools, persist events, or return approval decisions.
 * Original DSHAPP copyright is preserved under upstream MIT.
 */
const canonical=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,96}$/.test(x);
export class P113OriginalToolCallObservation {
  #records=[];
  #pending=new Map();
  #seen=new Set();
  #peak=0;
  begin({exec,handle,store}={}){
    const id=exec?.callId;
    let live=false;
    try{
      live=Boolean(canonical(id)&&handle&&handle.session&&
        canonical(handle.id)&&store?.get?.(handle.id)===handle.session&&
        exec?.signal?.aborted!==true);
    }catch{live=false;}
    const record={
      callId:canonical(id)?id:null,
      name:typeof exec?.name==='string'?exec.name:null,
      originalSessionLiveOnEntry:live,
      duplicate:canonical(id)&&this.#seen.has(id),
      settled:false,
      originalRuntimeInvocationObserved:true
    };
    this.#records.push(record);
    if(canonical(id))this.#seen.add(id);
    if(live&&!record.duplicate){
      this.#pending.set(id,record);
      this.#peak=Math.max(this.#peak,this.#pending.size);
    }
    return record;
  }
  end(record){
    if(!this.#records.includes(record)||record.settled)return;
    record.settled=true;
    if(record.callId&&this.#pending.get(record.callId)===record)
      this.#pending.delete(record.callId);
  }
  // Exact original session commits are inspected AFTER original AgentLoop has
  // completed. This doesn't independently prove pending native authority.
  verify({handle,store,calls,results,assistantEvents}={}){
    let stillLive=false;
    try{stillLive=Boolean(handle?.session&&store?.get?.(handle.id)===handle.session);}
    catch{}
    const rec=this.#records[0];
    const source=results?.[0]?.sourceEventSeqs;
    const linked=Array.isArray(calls)&&calls.length===1&&
      Array.isArray(results)&&results.length===1&&
      Array.isArray(source)&&source.length===1&&source[0]===calls[0].seq;
    const resultId=results?.[0]?.data?.message?.toolCallId;
    const committedToolId=assistantEvents?.[0]?.data?.message?.content
      ?.find?.(b=>b?.type==='tool-call')?.id;
    const observed=Boolean(stillLive&&this.#records.length===1&&
      rec?.originalSessionLiveOnEntry===true&&rec.settled===true&&
      rec.duplicate===false&&this.#peak===1&&this.#pending.size===0&&
      canonical(rec.callId)&&rec.callId===resultId&&
      rec.callId===committedToolId&&linked);
    return Object.freeze({
      observed,
      originalToolInvocationCount:this.#records.length,
      maxConcurrentObserved:this.#peak,
      originalSessionSameObject:stillLive,
      committedCallResultLinked:linked,
      callIdConsistent:rec?.callId===resultId&&rec?.callId===committedToolId,
      nativeAuthorization:false,
      androidBinderVerified:false,
      engineGenerationVerifiedByNative:false,
      exactOriginalPendingAtNative:false
    });
  }
}
