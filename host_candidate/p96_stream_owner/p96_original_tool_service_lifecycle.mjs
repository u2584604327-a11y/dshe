/**
 * Verify exact original Cordis service activation with in-memory,
 * no-I/O systemPrompt test dependency. No tools executed.
 */
import {Context} from '@deepseek-ai/cordis';
import {ToolRuntime} from '@deepseek-ai/dsh-tools';
const report=(k,v)=>process.stdout.write('P96_TOOL_ACTIVATION_'+k+'='+String(v)+'\n');
const ctx=new Context();
try{
 const owner=ctx.provide('systemPrompt',{
   tools(...args){
     report('SYSTEM_PROMPT_TOOLS_HOOK_REGISTERED',args.length);
     return () => {};
   }
 });
 report('PROVIDER_REGISTERED', typeof owner==='function');
 report('PROVIDED_SERVICE_READ', typeof ctx.get('systemPrompt'));
 report('PROVIDED_PROPERTY_READ', typeof ctx.systemPrompt);
 const fork=await ctx.plugin(ToolRuntime,{mode:'native',maxParallelSubCalls:1});
 report('FORK_TYPE',typeof fork);
 report('FORK_KEYS',Object.keys(fork||{}).slice(0,18).join(','));
 report('FORK_STATUS_INITIAL',fork?.status);
 // Let Cordis asynchronous dependency and service lifecycles settle.
 await new Promise(resolve=>setTimeout(resolve,30));
 const svc=ctx.get('tools')??ctx.tools;
 report('FORK_STATUS_AFTER_TICK',fork?.status);
 report('CTX_SERVICE_AFTER_TICK',typeof svc);
 report('SERVICE_REGISTER_METHOD',typeof svc?.register);
 report('SERVICE_EXECUTE_METHOD',typeof svc?.execute);
 report('REGISTRY_KEYS',Object.keys(ctx.registry||{}).slice(0,12).join(','));
}catch(e){
 report('ERROR_TYPE',e?.code||e?.name||'UNKNOWN');
 const message=String(e?.message||'').slice(0,180)
   .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>')
   .replace(/\/[A-Za-z0-9._/\-]+/g,'<PATH>');
 report('SAFE_ERROR_DETAIL',message);
}
finally{
 if(typeof ctx.dispose==='function')await ctx.dispose();
}
