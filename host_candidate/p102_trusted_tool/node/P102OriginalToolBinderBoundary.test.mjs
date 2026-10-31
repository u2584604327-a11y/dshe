import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {P102OriginalToolBinderBoundary as Boundary} from './P102OriginalToolBinderBoundary.mjs';

const SESSION='a'.repeat(64);
const call=()=>({sessionId:'p99_session_controller_once',callId:'call_p101_0001',
  toolName:'read_synthetic_fixture',args:{query:'fixture'}});
const terminal=()=>({callId:'call_p101_0001',status:'SUCCESS',
  outcomeUnknown:false,retrySafe:false,fixedResult:'fixture-read-success'});
function fixture(overrides={}){
  const metrics={bind:0,request:0,verified:0,revoke:0,frames:[]};
  const transport={
    async bind(){metrics.bind++;return {session:SESSION};},
    async request(frame){metrics.request++;metrics.frames.push(frame);return terminal();},
    revoke(){metrics.revoke++;}
  };
  const verify=async()=>{metrics.verified++;return true;};
  const boundary=new Boundary({transport:{...transport,...overrides.transport},
    assertOriginalCall:overrides.verify??verify,deadlineMs:overrides.deadlineMs??1000});
  return {boundary,metrics};
}
let checks=0;
async function expectBlocked(options,reason){
  const {boundary,metrics}=fixture(options);
  await assert.rejects(boundary.execute(options?.call??call()),new RegExp(reason));
  assert.notEqual(boundary.state,'COMPLETED');
  await assert.rejects(boundary.execute(call()),/P102_REPLAY_OR_CONCURRENT_CALL_DENIED/);
  checks++;
  return metrics;
}
test('exact original IDs and host session are preserved; one result only',async()=>{
  const {boundary,metrics}=fixture();
  assert.deepEqual(await boundary.execute(call()),{value:'fixture-read-success'});
  assert.equal(boundary.state,'COMPLETED');
  assert.equal(metrics.bind,1);assert.equal(metrics.request,1);
  assert.equal(metrics.verified,2);assert.equal(metrics.revoke,0);
  assert.deepEqual(metrics.frames[0],{session:SESSION,
    originalSessionId:'p99_session_controller_once',callId:'call_p101_0001',
    toolName:'read_synthetic_fixture',arguments:'{"query":"fixture"}'});
  await assert.rejects(boundary.execute(call()),/REPLAY_OR_CONCURRENT/);
  checks++;
});
test('invalid tool, arguments, call/session ID fail before native dispatch',async()=>{
  for(const mutation of [
    {toolName:'publish_comment'},{args:{query:'fixture',write:true}},
    {args:{query:'../../private'}},{args:null},{callId:'invalid id'},
    {sessionId:'../other'}
  ]){
    const m=await expectBlocked({call:{...call(),...mutation}},'NONCANONICAL');
    assert.equal(m.bind,0);assert.equal(m.request,0);
  }
});
test('original turn verification fails closed before binding',async()=>{
  const m=await expectBlocked({verify:async()=>false},'ORIGINAL_TURN_NOT_VERIFIED');
  assert.equal(m.bind,0);assert.equal(m.request,0);
});
test('invalid host session is never sent to native',async()=>{
  const m=await expectBlocked({transport:{bind:async()=>({session:'model-controlled'})}},'NATIVE_HOST_SESSION_INVALID');
  assert.equal(m.request,0);
});
test('native failure, spoof, unknown and extra fields all deny',async()=>{
  const variants=[
    {...terminal(),callId:'wrong'}, {...terminal(),status:'REJECTED'},
    {...terminal(),outcomeUnknown:true}, {...terminal(),retrySafe:true},
    {...terminal(),fixedResult:'untrusted'}, {...terminal(),injected:true},
    null,{},
  ];
  for(const v of variants)
    await expectBlocked({transport:{request:async()=>v}},'NATIVE_TERMINAL_UNVERIFIED');
});
test('stale original turn after native result never returns a value',async()=>{
  let seen=0;
  await expectBlocked({verify:async()=>++seen===1},'ORIGINAL_TURN_STALE_AFTER_NATIVE');
  assert.equal(seen,2);
});
test('concurrent second call is rejected while native approval pending',async()=>{
  let release;
  const {boundary}=fixture({transport:{request:()=>new Promise(r=>{release=r;})}});
  const first=boundary.execute(call());
  await assert.rejects(boundary.execute(call()),/REPLAY_OR_CONCURRENT/);
  await new Promise(r=>setImmediate(r));
  assert.equal(typeof release,'function');
  release(terminal());
  assert.deepEqual(await first,{value:'fixture-read-success'});
  checks++;
});
test('background revoke drops late terminal and never retries',async()=>{
  let release;
  const {boundary}=fixture({transport:{request:()=>new Promise(r=>{release=r;})}});
  const first=boundary.execute(call());
  await new Promise(r=>setImmediate(r));
  boundary.revoke();
  release(terminal());
  await assert.rejects(first,/P102_REVOKED/);
  assert.equal(boundary.state,'REVOKED');
  await assert.rejects(boundary.execute(call()),/REPLAY_OR_CONCURRENT/);
  checks++;
});
test('unknown transport outcome times out and cannot re-arm',async()=>{
  const {boundary}=fixture({transport:{request:()=>new Promise(()=>{})},deadlineMs:20});
  await assert.rejects(boundary.execute(call()),/NATIVE_RESULT_TIMEOUT_UNKNOWN_OUTCOME/);
  assert.equal(boundary.state,'BLOCKED_NO_RETRY');
  await assert.rejects(boundary.execute(call()),/REPLAY_OR_CONCURRENT/);
  checks++;
});
test('constructor rejects untrusted or incomplete adapters',()=>{
  for(const opts of [{},{transport:{}},{transport:{bind(){},request(){}}},
    {transport:{bind(){},request(){}},assertOriginalCall:()=>true,deadlineMs:10001}]){
    assert.throws(()=>new Boundary(opts),/TRUSTED_ORIGINAL_AND_NATIVE_PORT_REQUIRED/);
    checks++;
  }
});
test('source-level parity with Android trusted Messenger contract (not runtime Binder)',()=>{
  const gate=readFileSync(new URL('../src/com/dsh/android/p102/P102TrustedToolGate.java',import.meta.url),'utf8');
  const port=readFileSync(new URL('../android/com/dsh/android/p102/P102AndroidToolBinderPort.java',import.meta.url),'utf8');
  for(const literal of ['TOOL="read_synthetic_fixture"','FIXED_ARGS=','APPROVAL_WINDOW_MS=10_000L'])
    assert.ok(gate.includes(literal),'gate drift: '+literal);
  for(const literal of ['request.sendingUid','Process.isIsolatedUid(sender)',
    'fields.putString("callId",terminal.id)','fields.putString("fixedResult","fixture-read-success")',
    'fields.putBoolean("outcomeUnknown",terminal.outcomeUnknown)',
    'fields.putBoolean("retrySafe",terminal.retrySafe)'])
    assert.ok(port.includes(literal),'port drift: '+literal);
  for(const literal of ['originalSessionId','trustedOriginalCallVerifier',
    'P102TrustedToolGate.OriginalCallVerifier','Process.isIsolatedUid(sender)'])
    assert.ok(port.includes(literal),'native original session provenance missing: '+literal);
  for(const literal of ['OriginalCallVerifier','originalCallValid(originalSession,callId)',
    'originalCallValid(originalSessionId,pendingCallId)'])
    assert.ok(gate.includes(literal),'trusted original call recheck missing: '+literal);
  checks++;
});
process.on('beforeExit',()=>{
  assert.ok(checks>=26,'only '+checks+' checks');
  console.log('P102_NODE_TO_BINDER_CANDIDATE_GATE=PASS cases='+checks);
  console.log('P102_ORIGINAL_SESSION_NATIVE_PROVENANCE_CONTRACT=PASS');
  console.log('P102_ORIGINAL_TOOLRUNTIME_PRODUCTION_HOOK=NOT_WIRED');
  console.log('P102_REAL_DSH_NODE_TO_ANDROID_BINDER=NOT_TESTED');
  console.log('P102_NO_NETWORK_NO_DEVICE_SIDE_EFFECTS=PASS');
});
