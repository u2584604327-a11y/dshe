/**
 * Safe reflection-only contract inventory for exact original LlmRuntime.
 * No service construction/model/provider/network/file/tool/session action.
 */
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);

function contract(name){
  const fn=LlmRuntime.prototype?.[name];
  if(typeof fn!=='function')return null;
  const src=Function.prototype.toString.call(fn);
  const sig=src.match(/^[^(]*\(([^)]{0,500})\)/)?.[1]||'';
  const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const fields=[...src.matchAll(/this\??\.([A-Za-z_$][A-Za-z0-9_$]{0,90})/g)]
    .map(x=>x[1]).filter(safe);
  const paramFields={};
  for(const p of params){
    paramFields[p]=[...src.matchAll(new RegExp('\\b'+p+'\\??\\.([A-Za-z_$][A-Za-z0-9_$]{0,90})','g'))]
      .map(x=>x[1]).filter(safe);
    paramFields[p]=[...new Set(paramFields[p])].slice(0,40);
  }
  const calls=[...src.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,90}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,90}){1,5})\s*\(/g)]
    .map(x=>x[1]).filter(x=>x.split('.').every(safe));
  const literals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
    .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
  return {name,arity:fn.length,params,paramFields,
    thisFields:[...new Set(fields)].slice(0,50),
    memberCalls:[...new Set(calls)].slice(0,70),
    safeLiterals:[...new Set(literals)].slice(0,50),sourceSize:src.length};
}
const methods=Object.getOwnPropertyNames(LlmRuntime.prototype||{})
  .filter(x=>x!=='constructor'&&safe(x)&&typeof LlmRuntime.prototype[x]==='function')
  .sort();

const normalizeSrc=Function.prototype.toString.call(LlmRuntime.prototype.normalizeModelInfo);
const modelFields=['provider','id','name','description','context','inputModalities',
  'systemPromptUpdate','toolUpdate','defaultMaxTokens','reasoning'];
const validationShape={};
for(const field of modelFields){
  const direct='resolved.'+field;
  const token='resolved\\.'+field;
  const subFields=[...normalizeSrc.matchAll(
    new RegExp(token+'\\??\\.([A-Za-z_$][A-Za-z0-9_$]{0,80})','g')
  )].map(x=>x[1]).filter(safe);
  const comparisons=[];
  const rhsRe=new RegExp(
    token+'\\s*(===|!==|==|!=|<=|>=|<|>)\\s*(?:[\\'\"]([A-Za-z_$][A-Za-z0-9_$-]{0,60})[\\'\"]|([A-Za-z_$][A-Za-z0-9_$.]{0,100}))',
    'g'
  );
  for(const m of normalizeSrc.matchAll(rhsRe)){
    comparisons.push({operator:m[1],literal:m[2]||null,identifier:m[3]||null});
  }
  const nestedPaths=[...normalizeSrc.matchAll(
    new RegExp(token+'((?:\\??\\.[A-Za-z_$][A-Za-z0-9_$]{0,80}){1,4})','g')
  )].map(m=>m[1].replace(/\\?\\./g,'.')).slice(0,30);
  validationShape[field]={
    referenced:normalizeSrc.includes(direct),
    typeofChecks:normalizeSrc.includes('typeof '+direct)||
      normalizeSrc.includes('typeof('+direct+')'),
    arrayCheck:normalizeSrc.includes('Array.isArray('+direct+')'),
    integerCheck:normalizeSrc.includes('Number.isInteger('+direct+')')||
      normalizeSrc.includes('Number.isSafeInteger('+direct+')'),
    lengthCheck:normalizeSrc.includes(direct+'.length')||
      normalizeSrc.includes(direct+'?.length'),
    subFields:[...new Set(subFields)].slice(0,30),
    nestedPaths:[...new Set(nestedPaths)].slice(0,30),
    comparisons:comparisons.slice(0,20)
  };
}
process.stdout.write('P99_LLM_MODEL_VALIDATION_SHAPE='+JSON.stringify(validationShape)+'\n');
process.stdout.write('P99_LLM_RUNTIME_METHODS='+JSON.stringify(
  methods.map(name=>({name,arity:LlmRuntime.prototype[name].length})).slice(0,100))+'\n');
for(const name of methods){
  if(/register|registration|adapter|model|provider|resolve|stream|api|config|prepare|route/i.test(name)){
    process.stdout.write('P99_LLM_RUNTIME_CONTRACT='+JSON.stringify(contract(name))+'\n');
  }
}
process.stdout.write('P99_LLM_RUNTIME_REFLECTION_ONLY=PASS\n');
