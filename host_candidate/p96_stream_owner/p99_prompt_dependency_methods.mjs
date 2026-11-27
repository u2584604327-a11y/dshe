/**
 * Safe reflection of exact original methods that the SessionController prompt
 * path can call. No construction, invocation, model, network, file or tool.
 */
import {AgentDefaultModelConfig} from '@deepseek-ai/dsh-agent-default-model';
import {FileUploads} from '@deepseek-ai/dsh-client-file-upload';

const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);

function contract(Class,name){
  const fn=Class.prototype?.[name];
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
  const memberCalls=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,90}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,90}){1,5})\s*\(/g)]
    .map(x=>x[1]).filter(x=>x.split('.').every(safe));
  const literals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
    .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
  return {
    name,arity:fn.length,params,paramFields,
    thisFields:[...new Set(fields)].slice(0,40),
    memberCalls:[...new Set(memberCalls)].slice(0,60),
    safeLiterals:[...new Set(literals)].slice(0,40),
    sourceSize:src.length
  };
}
for(const [label,Class,names] of [
  ['AgentDefaultModelConfig',AgentDefaultModelConfig,['currentSelection','saveSelection']],
  ['FileUploads',FileUploads,['resolve','bindPrompt','commit','registerAgentResolver']],
]){
  for(const name of names){
    process.stdout.write('P99_PROMPT_DEP_METHOD='+JSON.stringify({
      label,contract:contract(Class,name)
    })+'\n');
  }
}
process.stdout.write('P99_PROMPT_DEP_METHOD_REFLECTION_ONLY=PASS\n');
