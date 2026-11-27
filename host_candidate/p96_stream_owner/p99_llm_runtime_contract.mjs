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

const genericChecks={};
for(const field of ['provider','id','name','description']){
  const token='resolved\\.'+field;
  const checks={types:[],comparisons:[]};
  const typeRe=new RegExp(
    "typeof\\s+resolved\\."+field+"\\s*(===|!==|==|!=)\\s*['\"]([A-Za-z]+)['\"]",
    'g'
  );
  for(const m of normalizeSrc.matchAll(typeRe)){
    checks.types.push({operator:m[1],type:m[2]});
  }
  const cmpRe=new RegExp(
    token+"\\s*(===|!==|==|!=)\\s*([A-Za-z_$][A-Za-z0-9_$.]{0,120})",
    'g'
  );
  for(const m of normalizeSrc.matchAll(cmpRe)){
    checks.comparisons.push({operator:m[1],identifier:m[2]});
  }
  genericChecks[field]=checks;
}
process.stdout.write('P99_LLM_GENERIC_MODEL_CHECKS='+JSON.stringify(genericChecks)+'\n');

const localBindings={};
for(const name of ['provider','context','reasoning']){
  const re=new RegExp(
    '\\b(?:const|let|var)\\s+'+name+'\\s*=\\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\\??\\.[A-Za-z_$][A-Za-z0-9_$]*){0,6})',
    'g'
  );
  localBindings[name]=[...normalizeSrc.matchAll(re)].map(m=>m[1]).slice(0,10);
}
process.stdout.write('P99_LLM_NORMALIZE_LOCAL_BINDINGS='+JSON.stringify(localBindings)+'\n');

const errorPredicateTokens={};
for(const code of ['INVALID_MODEL_INFO','INVALID_MODEL_CONTEXT','INVALID_MODEL_MAX_TOKENS','INVALID_MODEL_REASONING']){
  const idx=normalizeSrc.indexOf(code);
  if(idx<0){errorPredicateTokens[code]=[];continue;}
  const window=normalizeSrc.slice(Math.max(0,idx-900),idx);
  const tokenRe=/(resolved\.(?:provider|id|name|description|context|inputModalities|systemPromptUpdate|toolUpdate|defaultMaxTokens|reasoning)(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,80})?|typeof|===|!==|==|!=|<=|>=|<|>|void|undefined|string|number|boolean|provider|model|context|reasoning|length|Array\.isArray|Number\.isInteger|Number\.isSafeInteger)/g;
  errorPredicateTokens[code]=[...window.matchAll(tokenRe)].map(m=>m[1]).slice(-120);
}
process.stdout.write('P99_LLM_ERROR_PREDICATE_TOKENS='+JSON.stringify(errorPredicateTokens)+'\n');
process.stdout.write('P99_LLM_RUNTIME_METHODS='+JSON.stringify(
  methods.map(name=>({name,arity:LlmRuntime.prototype[name].length})).slice(0,100))+'\n');
for(const name of methods){
  if(/register|registration|adapter|model|provider|resolve|stream|api|config|prepare|route/i.test(name)){
    process.stdout.write('P99_LLM_RUNTIME_CONTRACT='+JSON.stringify(contract(name))+'\n');
  }
}
process.stdout.write('P99_LLM_RUNTIME_REFLECTION_ONLY=PASS\n');
