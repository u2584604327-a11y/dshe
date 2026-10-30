/**
 * Zero-side-effect Cordis Context contract probe from the SHA-locked original
 * runtime closure. Prints method names/arities and safe own-key types only.
 * No service plugin, session, network, model, tool, file, or Android action.
 */
import {Context} from '@deepseek-ai/cordis';

const safe=(s)=>/^[A-Za-z_$][A-Za-z0-9_$]{0,70}$/.test(s);
const methods=Object.getOwnPropertyNames(Context.prototype)
  .filter(name=>name!=='constructor'&&safe(name))
  .map(name=>{
    const value=Object.getOwnPropertyDescriptor(Context.prototype,name)?.value;
    return typeof value==='function'?{name,arity:value.length}:null;
  }).filter(Boolean).slice(0,80);

const ctx=new Context();
const own=Object.keys(ctx).filter(safe).slice(0,80).map(key=>{
  const value=ctx[key];
  return {key,type:Array.isArray(value)?'array':typeof value,nullValue:value===null};
});

process.stdout.write('P99_CORDIS_CONTEXT_METHODS='+JSON.stringify(methods)+'\n');
process.stdout.write('P99_CORDIS_CONTEXT_OWN_SHAPE='+JSON.stringify(own)+'\n');
process.stdout.write('P99_CORDIS_CONTEXT_GET_TYPE='+typeof ctx.get+'\n');
process.stdout.write('P99_CORDIS_CONTEXT_PLUGIN_TYPE='+typeof ctx.plugin+'\n');
process.stdout.write('P99_CORDIS_CONTEXT_NO_SERVICE_STARTED=PASS\n');
if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
