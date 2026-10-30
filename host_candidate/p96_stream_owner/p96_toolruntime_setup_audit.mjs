/**
 * Temporary structural inspection of SHA-locked original ToolRuntime.
 * Does not execute methods, instantiate tools, access user data or network.
 * Max 1500 chars per selected method in private CI. Remove after use.
 */
import {ToolRuntime} from '@deepseek-ai/dsh-tools';
import {Context} from '@deepseek-ai/cordis';

for (const key of ['constructor','register','execute','prepareExecution',
 'completeScheduledExecution','dispatchToolBody','createExecution','get']) {
 const fn=ToolRuntime.prototype[key];
 if(typeof fn!=='function')continue;
 const body=Function.prototype.toString.call(fn).slice(0,1700)
    .replace(/[\r\n\t]+/g,' ')
    .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>');
 process.stdout.write('P96_TOOL_RUNTIME_METHOD='+key+' BODY='+body+'\n');
}
const ctx=new Context();
process.stdout.write('P96_CORDIS_CONTEXT_PLUGIN_TYPE='+typeof ctx.plugin+'\n');
process.stdout.write('P96_CORDIS_CONTEXT_START_TYPE='+typeof ctx.start+'\n');
try{
 const obj=new ToolRuntime(ctx,{});
 process.stdout.write('P96_TOOL_RUNTIME_NEW=PASS\n');
 process.stdout.write('P96_TOOL_RUNTIME_NEW_CTX='+Boolean(obj.ctx)+'\n');
}catch(e){
 process.stdout.write('P96_TOOL_RUNTIME_NEW=BLOCKED_'+(e?.code||e?.name||'UNKNOWN')+'\n');
}
if(typeof ctx.dispose==='function')await ctx.dispose();
