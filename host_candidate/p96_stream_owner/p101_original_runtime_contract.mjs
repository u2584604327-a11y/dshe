/**
 * P101 exact-original service method shape, import/reflection only.
 * Does not instantiate services or execute tools/model/network/session.
 */
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
import {ToolRuntime} from '@deepseek-ai/dsh-tools';
import {AgentLoop} from '@deepseek-ai/dsh-agent-loop';
const safe=x=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(x);
function shape(klass){
  const names=Object.getOwnPropertyNames(klass.prototype||{}).filter(safe);
  return names.filter(x=>typeof klass.prototype[x]==='function').map(name=>{
    const fn=klass.prototype[name],src=Function.prototype.toString.call(fn);
    const sig=src.match(/^[^(]*\(([^)]{0,300})\)/)?.[1]||'';
    const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
    const calls=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){1,4})\s*\(/g)]
      .map(x=>x[1]).filter(x=>x.split('.').every(safe));
    const props=[...src.matchAll(/(?:this|ctx|input|options|request|call|exec|result|adapter|stream|signal)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})/g)]
      .map(x=>x[1]).filter(safe);
    return {name,arity:fn.length,params,memberCalls:[...new Set(calls)].slice(0,40),
      properties:[...new Set(props)].slice(0,40),sourceSize:src.length};
  }).filter(x=>/prepare|stream|call|execute|notify|register|resolve|model|agent|tool|run/i.test(x.name)).slice(0,45);
}
const rows={llm:shape(LlmRuntime),tools:shape(ToolRuntime),agentLoop:shape(AgentLoop)};
if(!rows.llm.some(x=>x.name==='registerAdapter')||
   !rows.tools.some(x=>x.name==='execute')||
   !rows.agentLoop.some(x=>x.name==='createAgent'))throw new Error('P101_ORIGINAL_METHOD_DRIFT');
process.stdout.write('P101_ORIGINAL_RUNTIME_METHOD_CONTRACT='+JSON.stringify(rows)+'\n');
process.stdout.write('P101_ORIGINAL_RUNTIME_REFLECTION_ONLY=PASS\n');
process.stdout.write('P101_REAL_TOOL_EXECUTION_AND_AGENT_CONTINUATION=NOT_TESTED\n');
