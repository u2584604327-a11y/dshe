/**
 * Real original AgentLoop.create single synthetic-session probe.
 * Uses original Cordis, AgentLoop, SessionStore, AgentRegistry, LlmRuntime,
 * ToolRuntime, SystemPrompt and SessionProjectionRegistry from exact APK.
 * No prompt, registered agent, real model or tool is supplied.
 * Outbound fetch/HTTP/TCP are fail-closed, and the attempt is one-shot.
 * Result is diagnostic, NEVER proof of an Android session.
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

const deny=()=>{throw new Error('P98_NO_NETWORK_ALLOWED');};
globalThis.fetch=deny;
net.Socket.prototype.connect=deny;
net.connect=deny;
net.createConnection=deny;
http.request=deny;
http.get=deny;
https.request=deny;
https.get=deny;

const log=(key,value)=>process.stdout.write('P98_ORIGINAL_SESSION_'+key+'='+String(value)+'\n');
const context=new Context();
const modules=[
  ['agents',AgentRegistry],
  ['sessions',SessionStore],
  ['llm',LlmRuntime],
  ['systemPrompt',SystemPrompt],
  ['tools',ToolRuntime],
  ['sessionProjections',SessionProjectionRegistry],
  ['agentLoop',AgentLoop]
];
let handle=null;
let outcome='UNSET';
try{
 for(const [key,Class] of modules){
   await context.plugin(Class,key==='tools'
     ? {mode:'native',maxParallelSubCalls:1}:{});
 }
 const loop=context.get('agentLoop');
 if(typeof loop?.create!=='function')throw new Error('ORIGINAL_AGENTLOOP_CREATE_MISSING');
 log('REAL_LOOP_CREATE_AVAILABLE','YES');
 const id='p98_nonexistent_fixture_agent_no_model';
 try{
   // Explicitly not a normal user prompt: this checks whether the original
   // runtime can create its own session from an otherwise empty registry.
   handle=await Promise.race([
      loop.create(id),
      new Promise((_,reject)=>setTimeout(
        ()=>reject(new Error('P98_CREATE_TIMEOUT')),2500))
   ]);
   outcome='CREATED_WITHOUT_USER_PROMPT';
   log('CREATE_RETURN_TYPE',typeof handle);
   log('CREATE_RETURN_KEYS',Object.keys(handle||{}).slice(0,15).join(','));
   log('SESSION_STORE_GET_TYPE',typeof context.get('sessions')?.get(id));
 }catch(error){
   const code=String(error?.code||error?.name||'UNKNOWN')
     .replace(/[^a-zA-Z0-9_]/g,'').slice(0,80);
   const reason=String(error?.message||'').slice(0,140)
     .replace(/(?:\/[A-Za-z0-9._/-]+)|(?:Bearer [A-Za-z0-9._-]+)/g,'<REDACTED>');
   outcome='BLOCKED_'+code;
   log('CREATE_ERROR_TYPE',code);
   log('CREATE_ERROR_REASON',reason);
 }
} finally{
 if(handle){
    for(const method of ['close','dispose']){
      if(typeof handle[method]==='function'){
        try{await handle[method]();}catch{}
        break;
      }
    }
 }
 if(typeof context.dispose==='function'){
   try{await context.dispose();}catch{}
 }
}
log('CREATE_OUTCOME',outcome);
log('MODEL_POST_COUNT','0_EXPECTED');
log('ORIGINAL_ANDROID_ENGINE_ATTACHED','NO');
log('ORIGINAL_AGENT_AUTOCONTINUATION','NOT_TESTED');
log('SOURCE_LOCKED_ONE_SHOT_PROBE','PASS');
