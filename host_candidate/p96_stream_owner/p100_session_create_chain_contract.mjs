/**
 * P100 exact-original session creation chain contract reflection.
 * Import/reflect only: no service construction, no session mutation, no model,
 * no tool, no network.
 */
import {AgentLoop} from '@deepseek-ai/dsh-agent-loop';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {SessionProjectionRegistry} from '@deepseek-ai/dsh-session-projection';

const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,80}$/.test(s);

function methodNames(klass){
  return Object.getOwnPropertyNames(klass.prototype||{})
    .filter(n=>n!=='constructor'&&safe(n)&&typeof klass.prototype[n]==='function')
    .sort();
}
function contract(label,klass,name){
  const fn=klass.prototype?.[name];
  if(typeof fn!=='function')return null;
  const src=Function.prototype.toString.call(fn);
  const sig=src.match(/^[^(]*\(([^)]{0,600})\)/)?.[1]||'';
  const params=sig.split(',').map(x=>x.trim()).filter(safe).slice(0,14);
  const optionFields=[...src.matchAll(/(?:options|config|sessionOptions|agentOptions)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})/g)]
    .map(x=>x[1]);
  const thisFields=[...src.matchAll(/this\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})/g)]
    .map(x=>x[1]);
  const calls=[...src.matchAll(/(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,80})\s*\(/g)]
    .map(x=>x[1]).filter(x=>!['if','for','while','switch','catch'].includes(x));
  const safeLiterals=[...src.matchAll(/['"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['"]/g)]
    .map(x=>x[1]);
  return {
    label,name,arity:fn.length,params,
    optionFields:[...new Set(optionFields)].slice(0,80),
    thisFields:[...new Set(thisFields)].slice(0,80),
    calledIdentifiers:[...new Set(calls)].slice(0,80),
    safeLiterals:[...new Set(safeLiterals)].slice(0,80),
    sourceSize:src.length
  };
}

const targets=[
  ['AgentLoop',AgentLoop],
  ['SessionStore',SessionStore],
  ['SessionProjectionRegistry',SessionProjectionRegistry]
];
for(const [label,klass] of targets){
  process.stdout.write('P100_CREATE_CHAIN_METHODS='+JSON.stringify({
    label,methods:methodNames(klass)
  })+'\n');
  for(const name of methodNames(klass)){
    if(!/(create|prepare|setup|publish|open|resume|hydrate|restore|projection|surface|session|cell|register)/i.test(name))continue;
    const row=contract(label,klass,name);
    if(row)process.stdout.write('P100_CREATE_CHAIN_CONTRACT='+JSON.stringify(row)+'\n');
  }
  const inject=klass.inject;
  if(Array.isArray(inject)){
    process.stdout.write('P100_CREATE_CHAIN_INJECT='+JSON.stringify({label,inject:inject.filter(safe)})+'\n');
  }
}
process.stdout.write('P100_CREATE_CHAIN_REFLECTION_ONLY=PASS\n');
