/**
 * SHA-locked original AgentLoop synthetic inbox exercise.
 * Real first-party Cordis, session, ToolRuntime, and AgentLoop; one fixed
 * synthetic message is queued using original handle.send(message,target,false)
 * to prevent driver wakeup. No model request, no tool, no UI, no Android.
 */
import {Context} from '@deepseek-ai/cordis';
import {AgentRegistry} from '@deepseek-ai/dsh-agent';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
import {ToolRuntime} from '@deepseek-ai/dsh-tools';
import {SystemPrompt} from '@deepseek-ai/dsh-system-prompt';
import {SessionProjectionRegistry} from '@deepseek-ai/dsh-session-projection';
import {AgentLoop} from '@deepseek-ai/dsh-agent-loop';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

let attemptedNetwork=0;
const denied=()=>{attemptedNetwork++;throw Error('NETWORK_DENIED');};
globalThis.fetch=denied;
net.Socket.prototype.connect=denied;
net.connect=denied;
http.request=denied;
http.get=denied;
https.request=denied;
https.get=denied;

const log=(k,v)=>process.stdout.write('P98_ORIGINAL_INBOX_'+k+'='+String(v)+'\n');
const ctx=new Context();
let handle;
try{
 for(const [name,cls] of [
  ['agents',AgentRegistry],['sessions',SessionStore],
  ['llm',LlmRuntime],['systemPrompt',SystemPrompt],
  ['tools',ToolRuntime],['sessionProjections',SessionProjectionRegistry],
  ['agentLoop',AgentLoop]
 ]){
   await ctx.plugin(cls,name==='tools'?{mode:'native',maxParallelSubCalls:1}:{});
 }
 const loop=ctx.get('agentLoop');
 handle=await loop.create('p98_synthetic_inbox_no_model');
 if(typeof handle?.send!=='function' || typeof handle?.inbox?.current!=='function')
   throw Error('ORIGINAL_HANDLE_SEND_INBOX_MISSING');
 const before=handle.inbox.current();
 const input={role:'user',content:[{type:'text',text:'synthetic safe message'}],
   timestamp:1};
 const result=handle.send(input,'followup',false);
 const after=handle.inbox.current();
 log('ORIGINAL_SEND_RETURN_TYPE',typeof result);
 log('BEFORE_TYPE',typeof before);
 log('AFTER_TYPE',typeof after);
 log('AFTER_KEYS',JSON.stringify(after&&typeof after==='object'
   ?Object.keys(after).slice(0,18):[]));
 log('NO_MODEL_NETWORK_ATTEMPTS',attemptedNetwork);
 if(attemptedNetwork!==0)throw Error('UNEXPECTED_NETWORK_ATTEMPT');
 if(before===after || after==null)
   throw Error('ORIGINAL_INBOX_NOT_OBSERVED_CHANGED');
 log('REAL_AGENTLOOP_INBOX_MUTATION','PASS');
 log('ORIGINAL_AGENTLOOP_AUTO_RUN','NOT_TESTED_DISABLED_WAKEUP');
 log('ANDROID_BROKER_UI','NOT_CONNECTED');
}catch(e){
 log('RESULT','BLOCKED_'+(e?.code||e?.name||'UNKNOWN'));
 log('ERROR',String(e?.message||'').slice(0,100).replace(/\/[\w/.-]+/g,'<PATH>'));
 process.exitCode=2;
}finally{
 if(handle){
  for(const op of ['close','dispose']){
   if(typeof handle[op]==='function'){
    try{await handle[op]();}catch{}break;
   }
  }
 }
 if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
}
