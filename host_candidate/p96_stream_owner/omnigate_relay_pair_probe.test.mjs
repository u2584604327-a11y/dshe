import test from 'node:test';
import assert from 'node:assert/strict';
import {parsePublicOrigin,probePair,correlatePair,localHealthCategory,remoteHealthCategory}
 from './omnigate_relay_pair_probe.mjs';
const tunnel='https://gw-example.claua.de/v1';
const ready={status:200,payload:{ok:true,listen:'127.0.0.1:8787',
  upstreamReachable:true,verifiedNativeOwner:'main',
  observedRuntimeRoute:'main_socket_and_driver_match'}};
const offline={status:503,payload:{error:'device_offline'}};
test('strict user supplied tunnel, no credentials, query or port',()=>{
 assert.equal(parsePublicOrigin(tunnel),'https://gw-example.claua.de');
 for(const bad of ['http://gw-example.claua.de','https://a.example.com',
  'https://a.claua.de:8443','https://user:password@a.claua.de',
  'https://a.claua.de/v1?key=secret','https://a.claua.de/fail'])
  assert.throws(()=>parsePublicOrigin(bad));
});
test('ready ADB-forwarded local Sidecar plus public 503 isolates relay path but does not prove registration root',async()=>{
 const calls=[];
 const r=await probePair({publicUrl:tunnel,request:async u=>{
   calls.push(u);return u.startsWith('http:')?ready:offline;
 }});
 assert.deepEqual(calls.sort(),['http://127.0.0.1:18787/health','https://gw-example.claua.de/health'].sort());
 assert.equal(r.verdict,'SIDECAR_READY_RELAY_REGISTRATION_OR_TARGET_UNVERIFIED');
 assert.equal(r.remote_category,'RELAY_DEVICE_OFFLINE');
 for(const key of ['issued_post','credentials_sent','remote_registration_verified','model_reply_verified'])
  assert.equal(r[key],false);
 assert.equal(JSON.stringify(r).includes('gw-example'),false);
});
test('public 503 and absent device is explicitly inconclusive about local readiness',async()=>{
 const r=await probePair({publicUrl:tunnel,request:async u=>{
  if(u.startsWith('http:'))throw Object.assign(Error('private secret'),{code:'ECONNREFUSED'});
  return offline;
 }});
 assert.equal(r.verdict,'RELAY_OFFLINE_DEVICE_LOCAL_READINESS_UNPROVEN');
 assert.equal(r.local_category,'LOCAL_DEVICE_NOT_OBSERVED');
 assert.equal(JSON.stringify(r).includes('private secret'),false);
});
test('local Sidecar 200 with unverified owner never reports original Native readiness',()=>{
 const h={...ready,payload:{...ready.payload,observedRuntimeRoute:'port_not_owned_by_main'}};
 assert.equal(localHealthCategory(h),'LOCAL_SIDECAR_ALIVE_NATIVE_OWNER_UNVERIFIED');
 assert.equal(correlatePair(localHealthCategory(h),'RELAY_DEVICE_OFFLINE'),
  'SIDECAR_ALIVE_RELAY_OFFLINE_AND_NATIVE_OWNER_UNVERIFIED');
});
test('public HTTP200 is not SSE/assistant success or 409 owner proof',async()=>{
 const r=await probePair({publicUrl:tunnel,request:async u=>u.startsWith('http:')?ready:
  {status:200,payload:{ok:true}}});
 assert.equal(r.verdict,'RELAY_NO_LONGER_503_REQUIRE_OGNET01_RECHECK');
 assert.equal(r.remote_registration_verified,false);
 assert.equal(r.model_reply_verified,false);
});
test('only exact relay offline signature classifies as device offline',()=>{
 assert.equal(remoteHealthCategory({status:503,payload:{error:'different'}}),
  'REMOTE_OTHER_RECHECK_OGNET01');
 assert.equal(remoteHealthCategory({status:503,payload:null}),
  'REMOTE_OTHER_RECHECK_OGNET01');
});
test('malformed local JSON / HTTP 200 without genuine Sidecar signature is not ready',()=>{
 assert.equal(localHealthCategory({status:200,payload:{ok:true}}),
  'LOCAL_ORIGINAL_SIDECAR_NOT_VERIFIED');
 assert.equal(localHealthCategory({status:401,payload:{}}),'LOCAL_HEALTH_HTTP_NON200');
});
console.log('OGNET02_ADB_PAIR_RELAY_503_NO_POST_NO_KEY=PASS');
console.log('OGNET02_OFFLINE_DOES_NOT_PROVE_RELAY_ROOT_OR_MODEL_REPLY=PASS');
