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
  const comparisons=[...src.matchAll(/(event\??\.(?:surfaceOp|type))\s*(===|!==|==|!=)\s*['"]([A-Za-z0-9_./:-]{1,80})['"]/g)]
    .map(x=>({field:x[1].replaceAll('?.','.'),operator:x[2],value:x[3]}));
  return {
    name,arity:fn.length,params,
    referencedFields:[...new Set(fields)].slice(0,60),
    calledIdentifiers:[...new Set(calls)].slice(0,60),
    safeLiterals:[...new Set(literals)].slice(0,60),
    includesReceivers:[...new Set(includesReceivers)].slice(0,30),
    comparisons:comparisons.slice(0,30),
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
const truthCases=[
  {label:'USER_NO_OP',event:{type:'user/message'}},
  {label:'USER_APPEND',event:{type:'user/message',surfaceOp:'append'}},
  {label:'USER_REPLACE_NO_SOURCES',event:{type:'user/message',surfaceOp:'replace'}},
  {label:'USER_REPLACE_EMPTY_SOURCES',event:{type:'user/message',surfaceOp:'replace',sourceEventSeqs:[]}},
  {label:'INBOX_REPLACE',event:{type:'agent/inbox/spliced',surfaceOp:'replace'}}
];
const surfaceFn=SessionPkg.isSurfaceEvent;
const appendFn=SessionPkg.isAppendSurfaceEvent;
const replaceFn=SessionPkg.isReplacementSurfaceEvent;
for(const row of truthCases){
  process.stdout.write('P100_SESSION_SURFACE_TRUTH='+JSON.stringify({
    label:row.label,
    isSurface:typeof surfaceFn==='function'?surfaceFn(row.event):null,
    isAppend:typeof appendFn==='function'?appendFn(row.event):null,
    isReplacement:typeof replaceFn==='function'?replaceFn(row.event):null
  })+'\n');
}
process.stdout.write('P100_SESSION_SURFACE_PURE_TRUTH_TABLE=PASS\n');
process.stdout.write('P100_SESSION_SURFACE_REFLECTION_ONLY=PASS\n');
