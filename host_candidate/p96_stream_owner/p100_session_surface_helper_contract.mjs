/**
 * P100 exact-original dsh-session surface helper contract reflection.
 * Import/reflect only: no session mutation, no model, no tool, no network.
 */
import * as SessionPkg from '@deepseek-ai/dsh-session';

const safeName=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,80}$/.test(s);
function contract(name,fn){
  const src=Function.prototype.toString.call(fn);
  const sig=src.match(/^[^(]*\(([^)]{0,500})\)/)?.[1]||'';
  const params=sig.split(',').map(x=>x.trim()).filter(safeName).slice(0,12);
  const fields=[...src.matchAll(/(?:event|input|value|surface|message|this)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})/g)]
    .map(x=>x[1]);
  const calls=[...src.matchAll(/(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(/g)]
    .map(x=>x[1]).filter(x=>!['if','for','while','switch','catch'].includes(x));
  const literals=[...src.matchAll(/['"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['"]/g)]
    .map(x=>x[1]);
  const includesReceivers=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})\??\.includes\s*\(/g)]
    .map(x=>x[1].replaceAll('?.','.'));
  return {
    name,arity:fn.length,params,
    referencedFields:[...new Set(fields)].slice(0,60),
    calledIdentifiers:[...new Set(calls)].slice(0,60),
    safeLiterals:[...new Set(literals)].slice(0,60),
    includesReceivers:[...new Set(includesReceivers)].slice(0,30),
    sourceSize:src.length
  };
}
const names=Object.keys(SessionPkg)
  .filter(safeName)
  .filter(x=>/(surface|replacement|append)/i.test(x))
  .sort();
process.stdout.write('P100_SESSION_SURFACE_EXPORT_NAMES='+JSON.stringify(names)+'\n');
for(const name of names){
  const value=SessionPkg[name];
  if(typeof value==='function'){
    process.stdout.write('P100_SESSION_SURFACE_CONTRACT='+JSON.stringify(contract(name,value))+'\n');
  }else{
    process.stdout.write('P100_SESSION_SURFACE_EXPORT_SHAPE='+JSON.stringify({name,type:typeof value})+'\n');
  }
}
process.stdout.write('P100_SESSION_SURFACE_REFLECTION_ONLY=PASS\n');
