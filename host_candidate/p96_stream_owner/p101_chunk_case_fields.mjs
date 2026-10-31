/**
 * P101 original BlockAssembler case-local required field inventory.
 * Safe property names only, no raw source, no execution or side effects.
 */
import {BlockAssembler} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(s);
function rows(fn){
 const src=Function.prototype.toString.call(fn);
 const cases=[...src.matchAll(/\bcase\s*['"]([^'"]{1,80})['"]\s*:/g)];
 return cases.map((m,i)=>{
  const segment=src.slice(m.index+m[0].length,i+1<cases.length?cases[i+1].index:src.length);
  const props=[...segment.matchAll(/(chunk|partial|this)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})(?:\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64}))?/g)]
    .map(x=>[x[1],x[2],x[3]].filter(Boolean).join('.')).filter(x=>x.split('.').every(safe));
  const calls=[...segment.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){0,3})\s*\(/g)]
    .map(x=>x[1]).filter(x=>x.split('.').every(safe));
  return {case:m[1],propertyPaths:[...new Set(props)].slice(0,30),
    calls:[...new Set(calls)].slice(0,30),bodyLength:segment.length};
 });
}
const output={push:rows(BlockAssembler.prototype.push),assemble:rows(BlockAssembler.prototype.assemble)};
process.stdout.write('P101_BLOCK_ASSEMBLER_CASE_FIELDS='+JSON.stringify(output)+'\n');
process.stdout.write('P101_BLOCK_ASSEMBLER_CASE_FIELDS_REFLECTION=PASS\n');
