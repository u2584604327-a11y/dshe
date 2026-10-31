/**
 * Safe reflection-only contract inventory for exact original LlmRuntime.
 * No service construction/model/provider/network/file/tool/session action.
 */
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);

function contract(name){
  const fn=LlmRuntime.prototype?.[name];
  if(typeof fn!=='function')return null;
  const src=Function.prototype.toString.call(fn);
  const sig=src.match(/^[^(]*\(([^)]{0,500})\)/)?.[1]||'';
  const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const fields=[...src.matchAll(/this\??\.([A-Za-z_$][A-Za-z0-9_$]{0,90})/g)]
    .map(x=>x[1]).filter(safe);
  const paramFields={};
  for(const p of params){
    paramFields[p]=[...src.matchAll(new RegExp('\\b'+p+'\\??\\.([A-Za-z_$][A-Za-z0-9_$]{0,90})','g'))]
      .map(x=>x[1]).filter(safe);
    paramFields[p]=[...new Set(paramFields[p])].slice(0,40);
  }
  const calls=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,90}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,90}){1,5})\s*\(/g)]
    .map(x=>x[1]).filter(x=>x.split('.').every(safe));
  const literals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
    .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
  return {name,arity:fn.length,params,paramFields,
    thisFields:[...new Set(fields)].slice(0,50),
    memberCalls:[...new Set(calls)].slice(0,70),
    safeLiterals:[...new Set(literals)].slice(0,50),sourceSize:src.length};
}
const methods=Object.getOwnPropertyNames(LlmRuntime.prototype||{})
  .filter(x=>x!=='constructor'&&safe(x)&&typeof LlmRuntime.prototype[x]==='function')
  .sort();
process.stdout.write('P99_LLM_RUNTIME_METHODS='+JSON.stringify(
  methods.map(name=>({name,arity:LlmRuntime.prototype[name].length})).slice(0,100))+'\n');
for(const name of methods){
  if(/register|model|provider|resolve|stream|api|config/i.test(name)){
    process.stdout.write('P99_LLM_RUNTIME_CONTRACT='+JSON.stringify(contract(name))+'\n');
  }
}
process.stdout.write('P99_LLM_RUNTIME_REFLECTION_ONLY=PASS\n');
