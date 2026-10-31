/**
 * P101 exact original chunk discriminator and synthetic BlockAssembler
 * preflight. No AgentLoop, tool, model, network or session side effects.
 */
import {BlockAssembler,AssistantStreamAccumulator} from '@deepseek-ai/dsh-llm';
const safe=s=>/^[A-Za-z][A-Za-z0-9_./:-]{0,70}$/.test(s);
function labels(fn){
  const src=Function.prototype.toString.call(fn);
  return [...new Set([...src.matchAll(/\bcase\s*['"]([^'"]{1,80})['"]\s*:/g)]
    .map(x=>x[1]).filter(safe))];
}
const block=labels(BlockAssembler.prototype.push);
const assemble=labels(BlockAssembler.prototype.assemble);
const accumulator=labels(AssistantStreamAccumulator.prototype.push);
process.stdout.write('P101_BLOCK_ASSEMBLER_CHUNK_CASES='+JSON.stringify(block)+'\n');
process.stdout.write('P101_BLOCK_ASSEMBLER_BLOCK_CASES='+JSON.stringify(assemble)+'\n');
process.stdout.write('P101_STREAM_ACCUMULATOR_CHUNK_CASES='+JSON.stringify(accumulator)+'\n');
if(block.length<3||accumulator.length<3)throw Error('P101_CHUNK_CASE_DRIFT');
const starts=block.filter(x=>/start|begin/i.test(x));
const deltas=block.filter(x=>/delta/i.test(x));
const ends=block.filter(x=>/end|stop|finish/i.test(x));
process.stdout.write('P101_BLOCK_CHUNK_CATEGORY_HINTS='+JSON.stringify({starts,deltas,ends})+'\n');
process.stdout.write('P101_ORIGINAL_CHUNK_DISCRIMINANTS=PASS\n');
process.stdout.write('P101_ORIGINAL_TOOLRUNTIME_AUTO_CONTINUATION=NOT_TESTED\n');
