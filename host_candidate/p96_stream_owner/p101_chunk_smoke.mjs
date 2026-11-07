/**
 * P101 first executable original BlockAssembler synthetic tool-call fixture.
 * No network, session, AgentLoop, ToolRuntime or side effects.
 */
import assert from 'node:assert/strict';
import {BlockAssembler} from '@deepseek-ai/dsh-llm';
const log=(k,v)=>process.stdout.write('P101_CHUNK_SMOKE_'+k+'='+String(v)+'\n');
const a=new BlockAssembler();
const chunks=[
 {type:'block-start',index:0,blockType:'tool-call'},
 {type:'tool-call-delta',index:0,id:'call_p101_0001',
  name:'read_synthetic_fixture',argumentsDelta:'{"query":"fixture"}'},
 {type:'block-end',index:0,block:{type:'toolCall',id:'call_p101_0001',name:'read_synthetic_fixture',arguments:{query:'fixture'}}},
 {type:'finish',reason:{kind:'tool-call'}}
];
try{
 for(const chunk of chunks){
   try{a.push(chunk);}
   catch(e){log('FAILED_CHUNK_TYPE',chunk.type);throw e;}
 }
 const envelope=a.assembled();
 log('ASSEMBLED_ENVELOPE_META',JSON.stringify({
   keys:envelope&&typeof envelope==='object'?Object.keys(envelope):[],
   response:envelope?.response&&typeof envelope.response==='object'
     ?{kind:envelope.response.kind,keys:Object.keys(envelope.response)}:envelope?.response,
   finish:envelope?.finish&&typeof envelope.finish==='object'
     ?{kind:envelope.finish.kind,keys:Object.keys(envelope.finish)}:envelope?.finish
 }));
 const blocks=a.blocks();
 log('BLOCKS',JSON.stringify(Array.isArray(blocks)?blocks.map(x=>({
   type:x?.type,name:x?.name,id:x?.id,
   argumentType:typeof x?.arguments,keys:x&&typeof x==='object'?Object.keys(x):[]
 })):[]));
 assert.ok(Array.isArray(blocks));
 assert.equal(blocks.length,1);
 assert.equal(blocks[0]?.name,'read_synthetic_fixture');
 assert.equal(blocks[0]?.id,'call_p101_0001');
 log('ORIGINAL_BLOCK_ASSEMBLER_TOOL_CALL','PASS');
 log('NETWORK_ATTEMPTS',0);
}catch(e){
 log('ORIGINAL_BLOCK_ASSEMBLER_TOOL_CALL','BLOCKED_'+String(e?.code||e?.name||'UNKNOWN'));
 log('REASON',String(e?.message||'').slice(0,150).replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>'));
 process.exitCode=2;
}
