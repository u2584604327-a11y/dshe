/**
 * P101 adapter prepareCall and stream consumption shape, exact-original
 * import/reflection only. No raw source, no session/model/tool/network.
 */
import * as llmModule from '@deepseek-ai/dsh-llm';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(s);
const methods=['prepareCall','adapterStream','streamWithRegistration','resolveCallWithInfo'];
function contract(name){
  const fn=LlmRuntime.prototype[name];
  if(typeof fn!=='function')throw Error('P101_METHOD_MISSING_'+name);
  const s=Function.prototype.toString.call(fn);
  const paths=[...s.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){1,5})/g)]
    .map(x=>x[1].replace(/\?\./g,'.')).filter(x=>x.split('.').every(safe));
  const calls=[...s.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){0,5})\s*\(/g)]
    .map(x=>x[1].replace(/\?\./g,'.')).filter(x=>x.split('.').every(safe));
  const returnKeys=[...s.matchAll(/return\s+(?:Object\.freeze\s*\()?\s*\{([\s\S]{0,1100}?)\}\s*\)?\s*;/g)]
    .flatMap(x=>[...x[1].matchAll(/(?:^|[,\n])\s*([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*(?::|\(|,|$)/g)].map(m=>m[1]))
    .filter(safe);
  const adapterCallRefs=[...s.matchAll(/adapterCall\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})/g)].map(x=>x[1]);
  const strings=[...s.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,50})['"]/g)]
    .map(x=>x[1]).filter(x=>/^(?:start|done|error|tool|toolCall|toolResult|assistant|user|message|stream|content|text|input|output|model|provider|callId|result|chunk|delta|tool_calls)$/.test(x));
  return {name,arity:fn.length,sourceSize:s.length,
    propertyPaths:[...new Set(paths)].slice(0,110),
    memberCalls:[...new Set(calls)].slice(0,100),
    returnKeys:[...new Set(returnKeys)].slice(0,40),
    adapterCallFields:[...new Set(adapterCallRefs)].slice(0,30),
    eventLiterals:[...new Set(strings)].slice(0,30)};
}
const exported=Object.keys(llmModule).filter(safe).sort();
const rows=methods.map(contract);
process.stdout.write('P101_ADAPTER_STREAM_METHOD_CONTRACT='+JSON.stringify(rows)+'\n');
process.stdout.write('P101_LLM_SAFE_EXPORT_IDENTIFIERS='+JSON.stringify(exported.slice(0,100))+'\n');
process.stdout.write('P101_ADAPTER_STREAM_REFLECTION_ONLY=PASS\n');
process.stdout.write('P101_ADAPTER_STREAM_RUNTIME_AND_TOOL_EXECUTION=NOT_TESTED\n');
