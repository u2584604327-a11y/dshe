/**
 * Real Cordis + original ToolRuntime service lifecycle probe.
 * Never calls execute, performs network, accesses device or reads user data.
 * No substitute ToolRuntime is created.
 */
import {Context} from '@deepseek-ai/cordis';
import {ToolRuntime} from '@deepseek-ai/dsh-tools';

const ctx=new Context();
const methods=['provide','set','get','plugin','inject','emit','on','effect','scope','registry','root','start','dispose'];
process.stdout.write('P96_CORDIS_METHOD_TYPES='+JSON.stringify(
  Object.fromEntries(methods.map(x=>[x,typeof ctx[x]])))+'\n');

function report(name,value) {
 process.stdout.write('P96_REAL_TOOL_SERVICE_'+name+'='+String(value)+'\n');
}
try {
 const state=ctx.plugin(ToolRuntime,{mode:'native',maxParallelSubCalls:1});
 report('PLUGIN_ATTACHED',true);
 report('PLUGIN_RETURN_TYPE',typeof state);
 report('SERVICE_VIA_CONTEXT',typeof ctx.get?.('tools'));
 report('SERVICE_VIA_PROPERTY',typeof ctx.tools);
 report('CONTEXT_SCOPE',typeof ctx.scope);
 report('SCOPE_STATUS',typeof ctx.scope?.status);
 if(typeof ctx.provide==='function'){
   try{
     const provided=ctx.provide('systemPrompt',{});
     report('SYNTHETIC_DEPENDENCY_PROVIDE', 'CALLED');
     report('SYNTHETIC_DEPENDENCY_RETURN_TYPE', typeof provided);
   }catch(e){
     report('SYNTHETIC_DEPENDENCY_PROVIDE', 'BLOCKED_'+(e?.code||e?.name||'UNKNOWN'));
   }
 }
 const service=ctx.get?.('tools')||ctx.tools;
 if(!service){
   report('REAL_REGISTRY', 'NO_SERVICE_WITHOUT_REQUIRED_INJECTIONS');
 }else{
   report('REAL_REGISTRY',typeof service.register);
 }
}catch(e){
 report('PLUGIN_ATTACHED',false);
 report('ERROR_TYPE',e?.code||e?.name||'UNKNOWN');
 // Do not print original stack, source path, or secrets.
}
finally{
 if(typeof ctx.dispose==='function') await ctx.dispose();
}
