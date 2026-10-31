/**
 * Safe contract probe for exact original principalOf() used by SessionController.
 * No service, prompt, network, model, tool, file or Android action.
 */
import {principalOf} from '@deepseek-ai/dsh-typert-protocol';

const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);
const src=Function.prototype.toString.call(principalOf);
const sig=src.match(/^[^(]*\(([^)]{0,400})\)/)?.[1]||'';
const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
const fields=[...src.matchAll(/(?:invocation|input|value|ctx)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,90})/g)]
  .map(x=>x[1]).filter(safe);
const literals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
  .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
process.stdout.write('P99_PRINCIPAL_CONTRACT='+JSON.stringify({
  arity:principalOf.length,params,referencedFields:[...new Set(fields)].slice(0,40),
  safeLiterals:[...new Set(literals)].slice(0,40),sourceSize:src.length
})+'\n');
try{
  const value=principalOf(undefined);
  process.stdout.write('P99_PRINCIPAL_UNDEFINED_RESULT='+JSON.stringify({
    type:typeof value,
    nullValue:value===null,
    keys:value&&typeof value==='object'?Object.keys(value).filter(safe).slice(0,30):[]
  })+'\n');
}catch(e){
  process.stdout.write('P99_PRINCIPAL_UNDEFINED_RESULT='+JSON.stringify({
    blocked:true,error:String(e?.code||e?.name||'UNKNOWN'),
    reason:String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>').slice(0,160)
  })+'\n');
}
process.stdout.write('P99_PRINCIPAL_CONTRACT_NO_SIDE_EFFECT=PASS\n');
