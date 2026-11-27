/**
 * OGNET01 public tunnel -> OmniGate read-only reachability classifier.
 * Works on a user-supplied *.claua.de HTTPS origin only. NEVER POSTs, adds
 * credentials, follows redirects, retries messages, reveals response bodies,
 * model IDs, IPs, tokens or hostnames in output.
 * Independently written: no GPL-3.0 source incorporated.
 */
import https from 'node:https';
import {pathToFileURL} from 'node:url';

const MAX_RESPONSE_BYTES=16384;
const REQUEST_TIMEOUT_MS=6000;
const ACTUAL_OWNER_ROUTES=Object.freeze({
  main:'main_socket_and_driver_match',
  overlay:'overlay_socket_and_driver_match'
});

export function parseTunnelBaseUrl(value){
  if(typeof value!=='string'||value.length>256)throw Error('TUNNEL_URL_INVALID');
  let url;
  try{url=new URL(value);}catch{throw Error('TUNNEL_URL_INVALID');}
  // Narrow scope: user's existing tunnel; not a general HTTP/SSRF proxy.
  if(url.protocol!=='https:'||!/^([a-z0-9-]+\.)+claua\.de$/i.test(url.hostname)||
     url.port||url.username||url.password||url.search||url.hash||
     !['/','/v1','/v1/'].includes(url.pathname))
    throw Error('TUNNEL_URL_OUT_OF_SCOPE');
  return url.origin;
}

export function classifyTransportFailure(error){
  const code=String(error?.code??'');
  if(['ENOTFOUND','EAI_AGAIN','ENODATA'].includes(code))return 'DNS_NO_ANSWER';
  if(['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'ERR_TLS_CERT_ALTNAME_INVALID','ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED'].includes(code))
    return 'TLS_CERT_REJECTED';
  if(['ETIMEDOUT','ERR_SOCKET_CONNECTION_TIMEOUT','ABORT_ERR','E_REMOTE_TIMEOUT'].includes(code))
    return 'PUBLIC_TUNNEL_TIMEOUT';
  if(['ECONNRESET','EPIPE','ERR_STREAM_PREMATURE_CLOSE'].includes(code))
    return 'PUBLIC_TUNNEL_RESET_OR_NO_REPLY';
  if(code==='ECONNREFUSED')return 'PUBLIC_TUNNEL_CONNECTION_REFUSED';
  if(code==='E_RESPONSE_TOO_LARGE')return 'REMOTE_RESPONSE_TOO_LARGE';
  return 'PUBLIC_TUNNEL_NETWORK_UNKNOWN';
}

/** No request body, no auth headers, no redirects and bounded read. */
export function getRemoteJson(origin,path){
  return new Promise((resolve,reject)=>{
    const url=new URL(path,origin);
    if(url.origin!==origin||!['/health','/v1/models'].includes(url.pathname))
      return reject(Object.assign(Error('restricted'),{code:'E_BAD_ROUTE'}));
    const req=https.request(url,{method:'GET',headers:{Accept:'application/json',
      'Cache-Control':'no-store'},agent:false,timeout:REQUEST_TIMEOUT_MS},res=>{
      let n=0;const chunks=[];
      res.on('data',b=>{
        n+=b.length;
        if(n>MAX_RESPONSE_BYTES){
          req.destroy(Object.assign(Error('oversize'),{code:'E_RESPONSE_TOO_LARGE'}));
          return;
        }
        chunks.push(b);
      });
      res.on('end',()=>{
        let payload=null;
        try{payload=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{}
        resolve({status:res.statusCode??0,payload});
      });
      res.on('error',reject);
    });
    req.on('timeout',()=>req.destroy(Object.assign(Error('timeout'),{code:'E_REMOTE_TIMEOUT'})));
    req.on('error',reject);
    req.end();
  });
}

export function classifyRemoteHealth({status,payload}={}){
  if(status===301||status===302||status===307||status===308)
    return 'PUBLIC_RELAY_REDIRECT_NOT_FOLLOWED';
  if(status===401||status===403)return 'PUBLIC_HEALTH_AUTH_OR_POLICY_DENIED';
  if(status===404)return 'PUBLIC_HEALTH_ROUTE_NOT_FOUND';
  if(status===409)return 'REMOTE_NATIVE_OWNER_MISMATCH_NO_POST';
  if(status===503&&payload?.error==='device_offline')return 'RELAY_DEVICE_OFFLINE';
  if(status===502||status===503||status===504)return 'PUBLIC_RELAY_OR_UPSTREAM_5XX';
  if(status!==200)return 'PUBLIC_HEALTH_HTTP_OTHER';
  if(!payload||typeof payload!=='object'||Array.isArray(payload))
    return 'PUBLIC_HEALTH_INVALID_JSON';
  if(payload.ok!==true)return 'PUBLIC_HEALTH_SERVICE_NOT_READY';
  if(payload.upstreamReachable!==true)return 'LOCAL_NATIVE_UPSTREAM_NOT_REACHABLE';
  const owner=payload.verifiedNativeOwner;
  if(!Object.hasOwn(ACTUAL_OWNER_ROUTES,owner)||
     payload.observedRuntimeRoute!==ACTUAL_OWNER_ROUTES[owner])
    return 'REMOTE_NATIVE_OWNER_UNVERIFIED_NO_POST';
  if(payload.ownerContinuity?.ambiguousOwners===true)
    return 'REMOTE_NATIVE_OWNER_AMBIGUOUS_NO_POST';
  return 'PUBLIC_HEALTH_OWNER_ADVISORY_OK';
}

/** A user-local diagnosis only. No POST, no model call, no auth/key read. */
export async function probeRemote({baseUrl,request=getRemoteJson}={}){
  const origin=parseTunnelBaseUrl(baseUrl);
  const report={probe:'DSH_OMNIGATE_REMOTE_READONLY_OGNET01',
    public_origin_redacted:true,issued_post:false,credentials_sent:false,
    model_turn_verified:false,assistant_reply_verified:false,
    automatic_retry:false,verdict:'NOT_CHECKED'};
  let health;
  try{health=await request(origin,'/health');}
  catch(e){report.verdict=classifyTransportFailure(e);return report;}
  report.health_http=Number(health?.status)||0;
  const category=classifyRemoteHealth(health);
  report.health_category=category;
  if(category!=='PUBLIC_HEALTH_OWNER_ADVISORY_OK'){
    report.verdict=category;return report;
  }
  let models;
  try{models=await request(origin,'/v1/models');}
  catch(e){report.verdict=classifyTransportFailure(e);return report;}
  report.models_http=Number(models?.status)||0;
  if(report.models_http===401||report.models_http===403){
    report.verdict='PUBLIC_MODEL_AUTH_OR_POLICY_REQUIRED';return report;
  }
  if(report.models_http!==200){
    report.verdict='PUBLIC_MODELS_HTTP_NON200';return report;
  }
  const values=models.payload?.data;
  if(!Array.isArray(values)||values.length===0||values.length>1000){
    report.verdict='PUBLIC_MODELS_EMPTY_OR_INVALID';return report;
  }
  report.verdict='PUBLIC_GET_READY_NO_SSE_OR_ASSISTANT_REPLY_PROOF';
  return report;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  if(process.argv.length!==3){
    process.stdout.write(JSON.stringify({probe:'DSH_OMNIGATE_REMOTE_READONLY_OGNET01',
      verdict:'REQUIRES_ONE_HTTPS_CLAUA_TUNNEL_URL',issued_post:false})+'\n');
    process.exitCode=2;
  }else{
    probeRemote({baseUrl:process.argv[2]}).then(report=>{
      process.stdout.write(JSON.stringify(report)+'\n');
      if(report.verdict!=='PUBLIC_GET_READY_NO_SSE_OR_ASSISTANT_REPLY_PROOF')
        process.exitCode=2;
    }).catch(()=>{
      process.stdout.write(JSON.stringify({probe:'DSH_OMNIGATE_REMOTE_READONLY_OGNET01',
        verdict:'INVALID_OR_OUT_OF_SCOPE_TUNNEL_URL',issued_post:false})+'\n');
      process.exitCode=2;
    });
  }
}