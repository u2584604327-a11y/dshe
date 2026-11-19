/**
 * P100 exact-original Session/Surface provenance contract.
 * Reflection only. No service construction, no session mutation, no model,
 * no tool, no network. Emits identifiers, types, safe literals, never bodies.
 */
import * as SessionPkg from '@deepseek-ai/dsh-session';
import * as SurfacePkg from '@deepseek-ai/dsh-session/surface';

const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,72}$/.test(s);
const methods=klass=>{
  if(typeof klass!=='function'||!klass.prototype)return [];
  return Object.getOwnPropertyNames(klass.prototype)
    .filter(n=>safe(n)&&typeof Object.getOwnPropertyDescriptor(klass.prototype,n)?.value==='function')
    .sort();
};
function contract(label,name,fn){
  const src=Function.prototype.toString.call(fn);
  const sig=src.match(/^[^(]*\(([^)]{0,500})\)/)?.[1]||'';
  const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const props=[...src.matchAll(/\b(this|event|data|entry|session|plan|surface|input|options|message|source)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,72})/g)]
    .map(x=>x[1]+'.'+x[2]);
  const calls=[...src.matchAll(/(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,72})\s*\(/g)]
    .map(x=>x[1]).filter(x=>!['if','for','while','switch','catch'].includes(x));
  const literals=[...src.matchAll(/['"]([A-Za-z][A-Za-z0-9_./:-]{1,72})['"]/g)]
    .map(x=>x[1]);
  const provenance=[...src.matchAll(/\b(sourceEventSeqs|surfaceOp|contentGeneration|applySurfacePlan|planSurfaceEvent|replaceGeneration|sourceEventSeq)\b/g)]
    .map(x=>x[1]);
  const result={
    label,name,arity:fn.length,params,
    propertyRefs:[...new Set(props)].slice(0,70),
    calledIdentifiers:[...new Set(calls)].slice(0,70),
    safeLiterals:[...new Set(literals)].slice(0,50),
    provenanceIdentifiers:[...new Set(provenance)].slice(0,20),
    sourceSize:src.length
  };
  process.stdout.write('P100_SURFACE_ORIGIN_METHOD='+JSON.stringify(result)+'\n');
}
const safeToken=/[A-Za-z_$][A-Za-z0-9_$]{0,72}|===|!==|==|!=|\?\?|&&|\|\||\?|:|\.|\[|\]|\{|\}|['"][A-Za-z0-9_./:-]{1,72}['"]/g;
function tokenWindows(src,needle){
  const rows=[];
  let from=0;
  while(true){
    const pos=src.indexOf(needle,from);
    if(pos<0)break;
    const window=src.slice(Math.max(0,pos-220),Math.min(src.length,pos+320));
    rows.push([...window.matchAll(safeToken)].map(x=>x[0]).slice(0,120));
    from=pos+needle.length;
  }
  return rows.slice(0,12);
}
function sessionAppendDetail(){
  const SessionClass=SessionPkg.Session;
  const fn=SessionClass?.prototype?.append;
  if(typeof fn!=='function')return {available:false};
  const src=Function.prototype.toString.call(fn);
  const entryProps=[...src.matchAll(/\bentry\??\.([A-Za-z_$][A-Za-z0-9_$]{0,72})/g)].map(x=>x[1]);
  const eventProps=[...src.matchAll(/\bevent\??\.([A-Za-z_$][A-Za-z0-9_$]{0,72})/g)].map(x=>x[1]);
  const objectKeys=[...src.matchAll(/(?:^|[,\{])\s*([A-Za-z_$][A-Za-z0-9_$]{0,72})\s*:/g)].map(x=>x[1]);
  return {
    available:true,
    arity:fn.length,
    entryProperties:[...new Set(entryProps)].slice(0,40),
    eventProperties:[...new Set(eventProps)].slice(0,40),
    lexicalObjectKeys:[...new Set(objectKeys)].slice(0,50),
    surfaceOpWindows:tokenWindows(src,'surfaceOp'),
    sourceEventSeqsWindows:tokenWindows(src,'sourceEventSeqs'),
    publicationEntryWindows:tokenWindows(src,'publicationEntry'),
    sourceSize:src.length
  };
}
process.stdout.write('P100_SESSION_APPEND_SURFACE_DETAIL='+JSON.stringify(sessionAppendDetail())+'\n');

const choices=[
  ...Object.entries(SessionPkg).map(([n,v])=>['session',n,v]),
  ...Object.entries(SurfacePkg).map(([n,v])=>['surface',n,v])
];
let observed=0;
for(const [group,name,value] of choices){
  if(!safe(name)||typeof value!=='function')continue;
  const ms=methods(value);
  const focus=ms.filter(n=>/^(constructor|append|commit|_processDelta|applySurfacePlan|planSurfaceEvent|_assertProjections|project|create|snapshotEvents|_state|addProjection|registerProjection)$/.test(n));
  if(!focus.length)continue;
  process.stdout.write('P100_SURFACE_ORIGIN_CLASS='+JSON.stringify({group,name,methods:focus})+'\n');
  for(const method of focus){
    const fn=Object.getOwnPropertyDescriptor(value.prototype,method)?.value;
    if(fn){contract(group+':'+name,method,fn);observed++;}
  }
}
process.stdout.write('P100_SURFACE_ORIGIN_METHOD_COUNT='+observed+'\n');
process.stdout.write('P100_SURFACE_ORIGIN_NO_MUTATION=PASS\n');
process.stdout.write('P100_SURFACE_ORIGIN_MODEL_AUTO_CALL=NOT_TESTED\n');
