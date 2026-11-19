import test from 'node:test';
import assert from 'node:assert/strict';
import {P113OriginalToolCallObservation} from './p113_original_tool_pending_observation.mjs';

function live(){
  const handle={id:'original_s1',session:{id:'original_s1'}};
  return {handle,store:new Map([[handle.id,handle.session]])};
}
function originalEvents(id='real_call1'){
  return {
    calls:[{type:'tool/call',seq:14}],
    results:[{type:'tool/result',sourceEventSeqs:[14],
      data:{message:{toolCallId:id}}}],
    assistantEvents:[{data:{message:{content:[
      {type:'tool-call',name:'read_synthetic_fixture',id}]}}}]
  };
}
test('actual entry/settlement and linked original events can only claim Node evidence',()=>{
  const {handle,store}=live(),p=new P113OriginalToolCallObservation();
  const record=p.begin({exec:{callId:'real_call1',name:'read_synthetic_fixture'},
    handle,store});
  const before=p.verify({handle,store,...originalEvents()});
  assert.equal(before.observed,false);
  p.end(record);
  const after=p.verify({handle,store,...originalEvents()});
  assert.equal(after.observed,true);
  assert.equal(after.nativeAuthorization,false);
  assert.equal(after.androidBinderVerified,false);
  assert.equal(after.exactOriginalPendingAtNative,false);
});
test('same-id substituted session fails object identity',()=>{
  const {handle,store}=live(),p=new P113OriginalToolCallObservation();
  store.set(handle.id,{id:handle.id});
  p.end(p.begin({exec:{callId:'real_call1'},handle,store}));
  assert.equal(p.verify({handle,store,...originalEvents()}).observed,false);
});
test('stale/removed session fails on result commit',()=>{
  const {handle,store}=live(),p=new P113OriginalToolCallObservation();
  const ticket=p.begin({exec:{callId:'real_call1'},handle,store});
  p.end(ticket);
  store.delete(handle.id);
  assert.equal(p.verify({handle,store,...originalEvents()}).observed,false);
});
test('pending records cannot be confused with completed or wrong source seq',()=>{
  const {handle,store}=live(),p=new P113OriginalToolCallObservation();
  const ticket=p.begin({exec:{callId:'real_call1'},handle,store});
  assert.equal(p.verify({handle,store,...originalEvents()}).observed,false);
  p.end(ticket);
  assert.equal(p.verify({handle,store,...originalEvents('other')}).observed,false);
  const wrong=originalEvents();wrong.results[0].sourceEventSeqs=[15];
  assert.equal(p.verify({handle,store,...wrong}).observed,false);
});
test('multiple and repeated same-call entries cannot pass',()=>{
  const {handle,store}=live(),p=new P113OriginalToolCallObservation();
  p.end(p.begin({exec:{callId:'real_call1'},handle,store}));
  p.end(p.begin({exec:{callId:'real_call1'},handle,store}));
  assert.equal(p.verify({handle,store,...originalEvents()}).observed,false);
});
test('signal abort, malformed ID and absent storage are not live pending proofs',()=>{
  for(const exec of [{callId:'real_call1',signal:{aborted:true}},
    {callId:'../../bad'},{callId:''},{callId:'a'.repeat(130)}]){
    const {handle,store}=live(),p=new P113OriginalToolCallObservation();
    p.end(p.begin({exec,handle,store}));
    assert.equal(p.verify({handle,store,...originalEvents()}).observed,false);
  }
  const {handle}=live(),p=new P113OriginalToolCallObservation();
  p.end(p.begin({exec:{callId:'real_call1'},handle,store:null}));
  assert.equal(p.verify({handle,store:null,...originalEvents()}).observed,false);
});
console.log('P113_NODE_ORIGINAL_TOOLRUNTIME_SESSION_LINK_UNIT=PASS');
console.log('P113_ANDROID_NATIVE_INDEPENDENT_PROOF=NOT_PROVEN');
