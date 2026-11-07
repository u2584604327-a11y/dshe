/**
 * P101 exact-original dsh-llm assistant chunk helper contract.
 * No execution, no raw source export, no model/tool/session/network.
 */
import {assistantStreamChunks,assembleAssistantStream,createAssistantMessage,
  createToolResultMessage,AssistantStreamAccumulator,BlockAssembler} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(s);
function contract(label,fn){
  if(typeof fn!=='function')throw Error('P101_CHUNK_EXPORT_MISSING_'+label);
  const src=Function.prototype.toString.call(fn);
  const signature=src.match(/^[^(]*\(([^)]{0,320})\)/)?.[1]||'';
  const params=signature.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const props=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){1,5})/g)]
    .map(x=>x[1].replace(/\?\./g,'.')).filter(x=>x.split('.').every(safe));
  const calls=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){0,5})\s*\(/g)]
    .map(x=>x[1].replace(/\?\./g,'.')).filter(x=>x.split('.').every(safe));
  const literals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,50})['"]/g)]
    .map(x=>x[1]).filter(x=>/^(?:start|done|error|tool|toolCall|toolResult|assistant|user|message|text|thinking|reasoning|content|block|delta|begin|end|stop|toolUse|tool_calls|tool_result|usage|finish|complete|final|tool_call|text_delta|toolCallStart|toolCallDelta|toolCallEnd)$/.test(x));
  return {label,arity:fn.length,params,sourceSize:src.length,
    propertyPaths:[...new Set(props)].slice(0,100),
    calls:[...new Set(calls)].slice(0,100),
    literals:[...new Set(literals)].slice(0,40)};
}
const out=[
  contract('assistantStreamChunks',assistantStreamChunks),
  contract('assembleAssistantStream',assembleAssistantStream),
  contract('createAssistantMessage',createAssistantMessage),
  contract('createToolResultMessage',createToolResultMessage),
  contract('AssistantStreamAccumulator',AssistantStreamAccumulator),
  contract('BlockAssembler',BlockAssembler)
];
for(const [label,klass] of [['AssistantStreamAccumulator',AssistantStreamAccumulator],['BlockAssembler',BlockAssembler]]){
  for(const key of Object.getOwnPropertyNames(klass.prototype||{}).filter(safe)){
    const descriptor=Object.getOwnPropertyDescriptor(klass.prototype,key);
    if(typeof descriptor?.value==='function'&&key!=='constructor')
      out.push(contract(label+'.'+key,descriptor.value));
  }
}
process.stdout.write('P101_ASSISTANT_CHUNK_HELPER_CONTRACT='+JSON.stringify(out)+'\n');
process.stdout.write('P101_ASSISTANT_CHUNK_REFLECTION_ONLY=PASS\n');
process.stdout.write('P101_REAL_AGENTLOOP_TOOL_ROUNDTRIP=NOT_TESTED\n');
