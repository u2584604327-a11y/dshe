import test from 'node:test';
import assert from 'node:assert/strict';
import {
  inspectOriginalApproval,
  installAdvisoryApprovalObserver
} from './p112_original_cordis_approval_observer.mjs';

function harness(){
  const session={id:'original_session_1'};
  const scope={scopeIdentity:'original_session_1'};
  const sessions=new Map([[session.id,session]]);
  const ctx={get(name){assert.equal(name,'sessions');return sessions;}};
  const scopeKeyOf=carrier=>carrier.scopeIdentity;
  const request={agent:{session},callId:'original_call_1',signal:{aborted:false}};
  return {scope,session,sessions,ctx,scopeKeyOf,request};
}
test('real-object identity + exact scope is only an advisory observation',()=>{
  const h=harness();
  const result=inspectOriginalApproval({
    request:h.request,ctx:h.ctx,scopeKeyOf:h.scopeKeyOf,carrier:h.scope
  });
  assert.deepEqual(result,{
    observed:true,sessionId:'original_session_1',callId:'original_call_1',
    proofLevel:'ORIGINAL_NODE_LIVE_SESSION_SCOPE_ONLY',
    nativeAuthorization:false,exactPendingToolRuntimeCall:false
  });
  assert.ok(Object.isFrozen(result));
});
test('rejects self-reported and substituted same-name session objects',()=>{
  const h=harness();
  const badRequest={...h.request,agent:{session:{id:h.session.id}}};
  const result=inspectOriginalApproval({
    request:badRequest,ctx:h.ctx,scopeKeyOf:h.scopeKeyOf,carrier:h.scope
  });
  assert.equal(result.observed,false);
  const wrong={...h.scope,scopeIdentity:'another_session'};
  assert.equal(inspectOriginalApproval({
    request:h.request,ctx:h.ctx,scopeKeyOf:h.scopeKeyOf,carrier:wrong
  }).observed,false);
});
test('rejects unknown, missing, malformed, overlong and cancelled tool calls',()=>{
  const h=harness();const check=extra=>inspectOriginalApproval({
    request:{...h.request,...extra},ctx:h.ctx,
    scopeKeyOf:h.scopeKeyOf,carrier:h.scope
  });
  for(const callId of [undefined,null,'',' ','.','a'.repeat(129),'call/../unsafe']){
    assert.equal(check({callId}).observed,false);
  }
  assert.equal(check({signal:{aborted:true}}).observed,false);
  h.sessions.delete(h.session.id);
  assert.equal(check({}).observed,false);
});
test('rejects a forged untrusted ctx, missing carrier and scope exceptions',()=>{
  const h=harness();
  const input={request:h.request,ctx:h.ctx,scopeKeyOf:h.scopeKeyOf,carrier:h.scope};
  assert.equal(inspectOriginalApproval({...input,carrier:null}).observed,false);
  assert.equal(inspectOriginalApproval({...input,ctx:{}}).observed,false);
  assert.equal(inspectOriginalApproval({...input,scopeKeyOf:()=>{throw Error('scope')}}).observed,false);
  assert.equal(inspectOriginalApproval({...input,ctx:{get:()=>{throw Error('services')}}}).observed,false);
});
test('Cordis approval waterfall remains delegated exactly once, never answered',async()=>{
  const h=harness();const callbacks=[];let onObserveCalls=0;let nextCalls=0;
  const observed=[];
  const ctx={...h.ctx,on(event,fn){callbacks.push([event,fn]);return ()=>{};}};
  installAdvisoryApprovalObserver({
    ctx,scopeKeyOf:h.scopeKeyOf,
    onObserve:info=>{onObserveCalls++;observed.push(info);}
  });
  assert.equal(callbacks.length,1);
  assert.equal(callbacks[0][0],'approval/request');
  const originalAnswer='rejected';
  const answer=await callbacks[0][1].call(h.scope,h.request,()=>{
    nextCalls++;return originalAnswer;
  });
  assert.equal(answer,originalAnswer);
  assert.equal(nextCalls,1);
  assert.equal(onObserveCalls,1);
  assert.equal(observed[0].nativeAuthorization,false);
  const denied=await callbacks[0][1].call({...h.scope,scopeIdentity:'forged'},h.request,()=>{
    nextCalls++;return 'unavailable';
  });
  assert.equal(denied,'unavailable');
  assert.equal(nextCalls,2);
  assert.equal(onObserveCalls,1);
});
test('observer diagnostics cannot override underlying approval decision',async()=>{
  const h=harness();let callback;let nextCount=0;
  const ctx={...h.ctx,on(e,fn){callback=fn;}};
  installAdvisoryApprovalObserver({
    ctx,scopeKeyOf:h.scopeKeyOf,onObserve(){throw Error('observer failure');}
  });
  assert.equal(await callback.call(h.scope,h.request,()=>{
    nextCount++;return 'cancelled';
  }),'cancelled');
  assert.equal(nextCount,1);
});
console.log('P112_ORIGINAL_CORDIS_SCOPE_PREFLIGHT_UNIT=PASS');
console.log('P112_ORIGINAL_CORDIS_WATERFALL_ALWAYS_DELEGATED=PASS');
console.log('P112_NATIVE_SESSION_CALL_ATTESTATION=NOT_PROVEN');
console.log('P112_ORIGINAL_PRODUCTION_BINDER=NOT_WIRED');
