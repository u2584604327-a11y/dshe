/**
 * OG-NET02: compare one user-initiated read-only public Relay health GET and
 * one ADB-forwarded original-device Sidecar health GET. No ADB invocation,
 * no keys, POST, redirects, retries, process action or port rotation.
 * The PC-only 18787 port must be explicitly forwarded by the user beforehand.
 */
import http from 'node:http';
import https from 'node:https';
import {pathToFileURL} from 'node:url';

const MAX_BYTES=16384;
const TIMEOUT_MS=6000;
const VERIFIED_ROUTES=Object.freeze({
  main:'main_socket_and_driver_match',
  overlay:'overlay_socket_and_driver_match'
});

export function parsePublicOrigin(value){
  if(typeof value!=='string'||value.length>256)throw Error('INVALID_PUBLIC_URL');
  let u;
  try{u=new URL(value);}catch{throw Error('INVALID_PUBLIC_URL');}
  if(u.protocol!=='https:'||!/^([a-z0-9-]+\.)+claua\.de$/i.test(u.hostname)||
     u.username||u.password||u.port||u.search||u.hash||
     !['/','/v1','/v1/'].includes(u.pathname))throw Error('INVALID_PUBLIC_URL');
  return u.origin;
}

/** Exactly one GET to an approved endpoint; follows no redirects. */
export function getHealth(url){
  return new Promise((resolve,reject)=>{
    const u=new URL(url);
    const isLocal=u.protocol==='http:'&&u.hostname==='127.0.0.1'&&u.port==='18787';
    const isRemote=u.protocol==='https:'&&/^([a-z0-9-]+\.)+claua\.de$/i.test(u.hostname)&&!u.port;
    if((!isLocal&&!isRemote)||u.pathname!=='/health'||u.search||u.hash||u.username||u.password)
      return reject(Object.assign(Error('RESTRICTED_TARGET'),{code:'E_RESTRICTED_TARGET'}));
    const transport=isLocal?http:https;
    const req=transport.request(u,{method:'GET',headers:{Accept:'application/json','Cache-Control':'no-store'},
      agent:false,timeout:TIMEOUT_MS},res=>{
      let len=0;const chunks=[];
      res.on('data',buf=>{
        len+=buf.length;
        if(len>MAX_BYTES)return req.destroy(Object.assign(Error('OVERSIZE'),{code:'E_RESPONSE_TOO_LARGE'}));
        chunks.push(buf);
      });
      res.on('end',()=>{
        let payload=null;
        try{payload=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{}
        resolve({status:res.statusCode??0,payload});
      });
      res.on('error',reject);
    });
    req.on('timeout',()=>req.destroy(Object.assign(Error('TIMEOUT'),{code:'E_TIMEOUT'})));
    req.on('error',reject);
    req.end();
  });
}

export function localHealthCategory(response){
  if(!response)return 'LOCAL_DEVICE_NOT_OBSERVED';
  if(response.status!==200)return 'LOCAL_HEALTH_HTTP_NON200';
  const h=response.payload;
  if(!h||h.ok!==true||h.listen!=='127.0.0.1:8787')
    return 'LOCAL_ORIGINAL_SIDECAR_NOT_VERIFIED';
  if(h.upstreamReachable===true&&
    Object.hasOwn(VERIFIED_ROUTES,h.verifiedNativeOwner)&&
    h.observedRuntimeRoute===VERIFIED_ROUTES[h.verifiedNativeOwner]&&
    h.ownerContinuity?.ambiguousOwners!==true)
    return 'LOCAL_SIDECAR_AND_NATIVE_OWNER_ADVISORY_OK';
  return 'LOCAL_SIDECAR_ALIVE_NATIVE_OWNER_UNVERIFIED';
}
export function remoteHealthCategory(response){
  if(!response)return 'REMOTE_PUBLIC_HEALTH_NOT_OBSERVED';
  if(response.status===503&&response.payload?.error==='device_offline')return 'RELAY_DEVICE_OFFLINE';
  if(response.status===200)return 'REMOTE_HTTP200_RECHECK_OGNET01_OWNER';
  return 'REMOTE_OTHER_RECHECK_OGNET01';
}
export function correlatePair(localCategory,remoteCategory){
  if(remoteCategory==='RELAY_DEVICE_OFFLINE'){
    if(localCategory==='LOCAL_SIDECAR_AND_NATIVE_OWNER_ADVISORY_OK')
      return 'SIDECAR_READY_RELAY_REGISTRATION_OR_TARGET_UNVERIFIED';
    if(localCategory==='LOCAL_SIDECAR_ALIVE_NATIVE_OWNER_UNVERIFIED')
      return 'SIDECAR_ALIVE_RELAY_OFFLINE_AND_NATIVE_OWNER_UNVERIFIED';
    return 'RELAY_OFFLINE_DEVICE_LOCAL_READINESS_UNPROVEN';
  }
  if(remoteCategory==='REMOTE_HTTP200_RECHECK_OGNET01_OWNER')
    return 'RELAY_NO_LONGER_503_REQUIRE_OGNET01_RECHECK';
  return 'RELAY_NON_503_OR_NETWORK_UNKNOWN_REQUIRE_OGNET01_RECHECK';
}
export async function probePair({publicUrl,request=getHealth}={}){
  const origin=parsePublicOrigin(publicUrl);
  const out={probe:'DSH_OMNIGATE_RELAY_PAIR_READONLY_OGNET02',
    local_probe:'adb_forward_127.0.0.1_18787',
    public_origin_redacted:true,credentials_sent:false,issued_post:false,
    retries:0,device_restart:false,ports_rotated:false,
    remote_registration_verified:false,model_reply_verified:false};
  const [local,remote]=await Promise.allSettled([
    request('http://127.0.0.1:18787/health'),request(origin+'/health')
  ]);
  out.local_health_http=local.status==='fulfilled'?Number(local.value?.status)||0:null;
  out.remote_health_http=remote.status==='fulfilled'?Number(remote.value?.status)||0:null;
  out.local_category=localHealthCategory(local.status==='fulfilled'?local.value:null);
  out.remote_category=remoteHealthCategory(remote.status==='fulfilled'?remote.value:null);
  out.verdict=correlatePair(out.local_category,out.remote_category);
  return out;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const url=process.argv.length===3?process.argv[2]:null;
  probePair({publicUrl:url}).then(out=>{
    process.stdout.write(JSON.stringify(out)+'\n');
    process.exitCode=out.verdict==='RELAY_NO_LONGER_503_REQUIRE_OGNET01_RECHECK'?0:2;
  }).catch(()=>{
    process.stdout.write(JSON.stringify({probe:'DSH_OMNIGATE_RELAY_PAIR_READONLY_OGNET02',
      verdict:'INVALID_URL_OR_PROBE_ERROR',issued_post:false,credentials_sent:false})+'\n');
    process.exitCode=2;
  });
}
