/**
 * Exact original agent/session entrypoint contract inventory.
 * Reflects imported SHA-pinned code without creating a session, executing
 * a tool, performing I/O or logging any code body / secrets.
 * Identifiers only; no original source file exported or archived.
 */
import {AgentLoop} from '@deepseek-ai/dsh-agent-loop';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {AgentRegistry} from '@deepseek-ai/dsh-agent';
import {SessionController} from '@deepseek-ai/dsh-api-session-controller';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';

const selected=[
  ['AgentLoop',AgentLoop,['create','resume','resumeWith','prepare']],
  ['SessionStore',SessionStore,['create','get','update','append','createSession']],
  ['AgentRegistry',AgentRegistry,['register','get','create']],
  ['SessionController',SessionController,['prompt','follow','liveProjections']],
  ['LlmRuntime',LlmRuntime,['stream','generate','create','get']]
];
const safe=(s)=>/^[A-Za-z_$][A-Za-z0-9_$]{0,70}$/.test(s);
function info(klass,method){
  const fn=klass.prototype?.[method];
  if(typeof fn!=='function')return null;
  const body=Function.prototype.toString.call(fn);
  const declared=body.match(/^[^(]*\(([^)]{0,450})\)/)?.[1]??'';
  const params=declared.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const propertyNames=[...body.matchAll(/(?:this|args|options|input|params|session|turn|request|signal)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,70})/g)]
    .map(x=>x[1]).filter(safe);
  const calls=[...body.matchAll(/(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,70})\s*\(/g)]
    .map(x=>x[1]).filter(x=>safe(x)&&!['if','for','while','switch','catch'].includes(x));
  const safeLiterals=[...body.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,40})['"]/g)]
    .map(x=>x[1]).filter(x=>/^(?:user|assistant|tool|prompt|follow|session|agent|message|content|text|timezone|timeZone|clientTimeZone|principal|id|sessionId|agentId|command|commands|next-turn|next-step)$/.test(x));
  const commandMethods=[...body.matchAll(/this\.commands\??\.([A-Za-z_$][A-Za-z0-9_$]{0,70})/g)]
    .map(x=>x[1]).filter(safe);
  const ctxMethods=[...body.matchAll(/this\.ctx\??\.([A-Za-z_$][A-Za-z0-9_$]{0,70})/g)]
    .map(x=>x[1]).filter(safe);
  const requestFields=[...body.matchAll(/request\??\.([A-Za-z_$][A-Za-z0-9_$]{0,70})/g)]
    .map(x=>x[1]).filter(safe);
  const signalFields=[...body.matchAll(/signal\??\.([A-Za-z_$][A-Za-z0-9_$]{0,70})/g)]
    .map(x=>x[1]).filter(safe);
  return {
    method,arity:fn.length,params,
    propertyNames:[...new Set(propertyNames)].slice(0,40),
    requestFields:[...new Set(requestFields)].slice(0,40),
    signalFields:[...new Set(signalFields)].slice(0,20),
    safeLiterals:[...new Set(safeLiterals)].slice(0,30),
    commandMethods:[...new Set(commandMethods)].slice(0,30),
    ctxMethods:[...new Set(ctxMethods)].slice(0,30),
    calledIdentifiers:[...new Set(calls)].slice(0,45),
    isAsync:fn.constructor?.name==='AsyncFunction',
    sourceSize:body.length
  };
}
function safeStaticShape(value){
  if(Array.isArray(value))return {type:'array',values:value.filter(x=>typeof x==='string'&&safe(x)).slice(0,30)};
  if(typeof value==='function')return {type:'function',name:safe(value.name||'')?value.name:'UNKNOWN',arity:value.length};
  if(value&&typeof value==='object'){
    const out={type:'object',keys:[]};
    for(const key of Object.keys(value).filter(safe).slice(0,30)){
      const v=value[key];
      let shape={key,type:Array.isArray(v)?'array':typeof v};
      if(typeof v==='string'&&safe(v))shape.value=v;
      if(Array.isArray(v))shape.values=v.filter(x=>typeof x==='string'&&safe(x)).slice(0,20);
      out.keys.push(shape);
    }
    return out;
  }
  return {type:typeof value};
}
function safeConstructorContract(klass){
  const source=Function.prototype.toString.call(klass);
  const m=source.match(/constructor\(([^)]{0,300})\)/);
  const params=(m?.[1]||'').split(',').map(x=>x.trim()).filter(safe).slice(0,10);
  const assigns=[...source.matchAll(/this\.([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*([A-Za-z_$][A-Za-z0-9_$]{0,64})/g)]
    .map(x=>({field:x[1],from:x[2]})).filter(x=>safe(x.field)&&safe(x.from)).slice(0,20);
  return {params,assigns};
}
for(const [label,klass,focus] of selected){
  const methods=focus.map(x=>info(klass,x)).filter(Boolean);
  const staticKeys=Object.getOwnPropertyNames(klass)
    .filter(x=>safe(x)&&!['length','name','prototype'].includes(x)).slice(0,25);
  const staticShapes={};
  for(const key of staticKeys)staticShapes[key]=safeStaticShape(klass[key]);
  process.stdout.write('P98_ORIGINAL_ENTRYPOINT='+label+' '+JSON.stringify({
    constructorArity:klass.length,
    constructorContract:safeConstructorContract(klass),
    staticKeys,staticShapes,methods
  })+'\n');
}
process.stdout.write('P98_ORIGINAL_ENTRYPOINT_SOURCE_ONLY=PASS\n');
process.stdout.write('P98_ORIGINAL_SESSION_CREATED=NO\n');
