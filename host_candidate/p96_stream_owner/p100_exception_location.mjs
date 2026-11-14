/**
 * P100 in-process, fail-closed exception-frame observer. CI-only.
 * Inspects the exact original P99 one-turn harness without patching the
 * original DSH runtime, session, event, controller, or listener callbacks.
 * Emits safe function identifiers and source positions; never source or data.
 */
import inspector from 'node:inspector';

const session=new inspector.Session();
const matched=[];
const scriptPackages=new Map();
const safeIdentifier=value=>typeof value==='string' &&
  /^[A-Za-z_$][A-Za-z0-9_$]{0,100}$/.test(value)?value:'UNKNOWN';
const packageLabel=url=>{
  if(typeof url!=='string')return 'unknown';
  if(url.includes('/@deepseek-ai/dsh-agent-loop/'))return 'dsh-agent-loop';
  if(url.includes('/@deepseek-ai/dsh-session/'))return 'dsh-session';
  if(url.includes('/@deepseek-ai/dsh-surface/'))return 'dsh-surface';
  if(url.includes('/@deepseek-ai/cordis/'))return 'cordis';
  const pkg=url.match(/\/@deepseek-ai\/([a-z][a-z0-9-]{0,70})\//);
  if(pkg)return pkg[1];
  if(url.includes('/p99_session_controller_prompt_once.mjs'))return 'p99-probe';
  if(url.startsWith('node:'))return 'node-internal';
  return 'other';
};
const post=(method,params={})=>new Promise((resolve,reject)=>{
  session.post(method,params,(error,result)=>error?reject(error):resolve(result));
});
session.connect();
session.on('Debugger.scriptParsed',({params})=>{
  if(typeof params?.scriptId==='string')
    scriptPackages.set(params.scriptId,packageLabel(params.url));
});
session.on('Debugger.paused',({params})=>{
  try{
    // The description is compared against a fixed, known error class only.
    // It is NEVER logged, nor are receiver values or call frame locals.
    if((params?.reason==='exception'||params?.reason==='promiseRejection') &&
       typeof params?.data?.description==='string' &&
       params.data.description.includes("Cannot read properties of undefined (reading 'includes')") &&
       matched.length<8){
      matched.push({
        reason:'undefined-includes',
        frames:(params.callFrames||[]).slice(0,16).map(frame=>({
          name:safeIdentifier(frame.functionName),
          package:scriptPackages.get(frame.location?.scriptId)||'unknown',
          line:typeof frame.location?.lineNumber==='number'?frame.location.lineNumber+1:null,
          column:typeof frame.location?.columnNumber==='number'?frame.location.columnNumber+1:null
        }))
      });
    }
  }finally{
    // No exception suppression, no modified runtime callbacks.
    session.post('Debugger.resume',{},()=>{});
  }
});
try{
  await post('Debugger.enable');
  await post('Debugger.setPauseOnExceptions',{state:'all'});
  await import('./p99_session_controller_prompt_once.mjs');
  await new Promise(resolve=>setTimeout(resolve,50));
  process.stdout.write('P100_EXCEPTION_LOCATION_META='+JSON.stringify(matched)+'\n');
  process.stdout.write('P100_EXCEPTION_LOCATION_OBSERVED='+(matched.length?'PASS':'NOT_OBSERVED')+'\n');
  process.stdout.write('P100_EXCEPTION_ORIGINAL_RUNTIME_UNPATCHED=YES\n');
  // No matching exception is an expected outcome after the boundary repair.
  // The CI separately requires the original automatic model call as proof.
}finally{
  await post('Debugger.setPauseOnExceptions',{state:'none'}).catch(()=>{});
  session.disconnect();
}
