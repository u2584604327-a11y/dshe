import test from 'node:test';
import assert from 'node:assert/strict';
import {parseTunnelBaseUrl,probeRemote,classifyRemoteHealth,classifyTransportFailure}
  from './omnigate_remote_preflight.mjs';

const host='https://gw-example.claua.de/v1';
const ready={ok:true,listen:'127.0.0.1:8787',upstreamReachable:true,
  verifiedNativeOwner:'main',observedRuntimeRoute:'main_socket_and_driver_match'};
function transport(health,models={status:200,payload:{data:[{id:'not-exported'}]}}){
  const calls=[];
  return {calls,request:async(origin,path)=>{
    calls.push({origin,path});return path==='/health'?health:models;
  }};
}
test('only user-supplied scoped HTTPS public tunnel; never include credentials or path overrides',()=>{
  assert.equal(parseTunnelBaseUrl(host),'https://gw-example.claua.de');
  for(const input of ['http://gw-example.claua.de','https://127.0.0.1',
    'https://localhost','https://attacker.example','https://gw-example.claua.de:8443',
    'https://user:secret@gw-example.claua.de',
    'https://gw-example.claua.de/health?token=secret',
    'https://gw-example.claua.de/v1/chat/completions',
    'https://gw-example.claua.de#fragment'])
    assert.throws(()=>parseTunnelBaseUrl(input));
});
test('remote health and models GET only, never sends messages or auth and never claims reply',async()=>{
  const t=transport({status:200,payload:ready});
  const r=await probeRemote({baseUrl:host,request:t.request});
  assert.equal(r.verdict,'PUBLIC_GET_READY_NO_SSE_OR_ASSISTANT_REPLY_PROOF');
  assert.equal(r.model_turn_verified,false);
  assert.equal(r.assistant_reply_verified,false);
  assert.equal(r.credentials_sent,false);
  assert.equal(r.issued_post,false);
  assert.equal(r.public_origin_redacted,true);
  assert.equal(JSON.stringify(r).includes('gw-example'),false);
  assert.deepEqual(t.calls.map(x=>x.path),['/health','/v1/models']);
});
test('relay 503 device_offline stops before model list, no retry or POST',async()=>{
  const t=transport({status:503,payload:{error:'device_offline'}});
  const r=await probeRemote({baseUrl:host,request:t.request});
  assert.equal(r.verdict,'RELAY_DEVICE_OFFLINE');assert.equal(t.calls.length,1);
});
test('original owner mismatch/ambiguous 409 and health not ready fail closed',async()=>{
  for(const health of [
    {status:409,payload:{error:'original_runtime_owner_mismatch'}},
    {status:200,payload:{...ready,observedRuntimeRoute:'port_not_owned_by_main'}},
    {status:200,payload:{...ready,ownerContinuity:{ambiguousOwners:true}}},
    {status:200,payload:{...ready,upstreamReachable:false}},
  ]){
    const t=transport(health),r=await probeRemote({baseUrl:host,request:t.request});
    assert.notEqual(r.verdict,'PUBLIC_GET_READY_NO_SSE_OR_ASSISTANT_REPLY_PROOF');
    assert.equal(t.calls.length,1);
  }
});
test('remote health auth, redirects and relay 5xx distinct from model no reply',async()=>{
  for(const [status,code] of [[401,'PUBLIC_HEALTH_AUTH_OR_POLICY_DENIED'],
    [307,'PUBLIC_RELAY_REDIRECT_NOT_FOLLOWED'],
    [502,'PUBLIC_RELAY_OR_UPSTREAM_5XX'],
    [404,'PUBLIC_HEALTH_ROUTE_NOT_FOUND']])
    assert.equal(classifyRemoteHealth({status,payload:null}),code);
});
test('model auth, empty models, and invalid public model metadata never masquerade as ready',async()=>{
  for(const [models,code] of [
    [{status:401,payload:{}},'PUBLIC_MODEL_AUTH_OR_POLICY_REQUIRED'],
    [{status:200,payload:{data:[]}},'PUBLIC_MODELS_EMPTY_OR_INVALID'],
    [{status:503,payload:null},'PUBLIC_MODELS_HTTP_NON200']]){
    const r=await probeRemote({baseUrl:host,request:transport({status:200,payload:ready},models).request});
    assert.equal(r.verdict,code);
  }
});
test('no reply / DNS / TLS / timeout are distinct sanitized failures',async()=>{
  for(const [code,expected] of [['ENOTFOUND','DNS_NO_ANSWER'],
    ['ECONNRESET','PUBLIC_TUNNEL_RESET_OR_NO_REPLY'],
    ['ETIMEDOUT','PUBLIC_TUNNEL_TIMEOUT'],
    ['ERR_TLS_CERT_ALTNAME_INVALID','TLS_CERT_REJECTED']]){
    assert.equal(classifyTransportFailure({code}),expected);
    const r=await probeRemote({baseUrl:host,request:async()=>{throw Object.assign(Error('secret body'),{code});}});
    assert.equal(r.verdict,expected);assert.equal(JSON.stringify(r).includes('secret'),false);
  }
});
console.log('OGNET01_REMOTE_PUBLIC_TUNNEL_LAYER_CLASSIFICATION=PASS');
console.log('OGNET01_NO_POST_NO_KEY_NO_RETRY_NO_UNVERIFIED_REPLY=PASS');