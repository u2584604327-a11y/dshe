/**
 * Exact original LlmRuntime with a synthetic local test adapter.
 * The adapter resolves model metadata but prepareCall always fails closed.
 * No network/model generation/tool/session/user data.
 */
import {Context} from '@deepseek-ai/cordis';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

let networkAttempts=0,prepareCalls=0;
const deny=()=>{networkAttempts++;throw new Error('P99_NETWORK_DENIED');};
globalThis.fetch=deny;
net.Socket.prototype.connect=deny;
net.connect=deny;
net.createConnection=deny;
http.request=deny;
http.get=deny;
https.request=deny;
https.get=deny;

const log=(k,v)=>process.stdout.write('P99_LOCAL_LLM_'+k+'='+String(v)+'\n');
const ctx=new Context();
let unregister=null;
try{
  await ctx.plugin(LlmRuntime,{});
  const llm=ctx.get('llm');
  const adapter={
    providerInfo(provider){return {id:provider,name:'P99 Local Fixture'};},
    providerRetryPolicy(){return undefined;},
    async resolveModel(model){
      return {
        id:model,
        name:'P99 Local Fixture Model',
        description:'Synthetic local metadata only',
        context:8192,
        inputModalities:['text'],
        systemPromptUpdate:'in-history',
        toolUpdate:'addition-only',
        defaultMaxTokens:128
      };
    },
    async prepareCall(){
      prepareCalls++;
      throw new Error('P99_MODEL_WAKEUP_FAIL_CLOSED');
    }
  };
  unregister=llm.registerAdapter(['p99-local'],adapter);
  log('REGISTERED',typeof unregister==='function'?'PASS':'YES_NONFUNCTION_DISPOSER');
  const signal=new AbortController().signal;
  const info=await llm.resolveModelInfo('p99-local','p99-model',signal);
  log('MODEL_INFO',JSON.stringify({
    provider:info?.provider,
    id:info?.id,
    name:info?.name,
    context:info?.context,
    inputModalities:info?.inputModalities,
    defaultMaxTokens:info?.defaultMaxTokens,
    reasoning:info?.reasoning??null
  }));
  if(info?.provider!=='p99-local'||info?.id!=='p99-model')
    throw new Error('P99_LOCAL_MODEL_INFO_NOT_NORMALIZED');
  log('RESOLVE_MODEL_INFO','PASS');
  log('PREPARE_CALLS',prepareCalls);
  log('NETWORK_ATTEMPTS',networkAttempts);
  if(prepareCalls!==0||networkAttempts!==0)throw new Error('P99_LOCAL_ADAPTER_SIDE_EFFECT');
  log('FAIL_CLOSED_PREPARE_NOT_INVOKED','PASS');
}catch(e){
  const reason=String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
    .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,180);
  log('RESULT','BLOCKED_'+String(e?.code||e?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,''));
  log('REASON',reason);
  log('PREPARE_CALLS',prepareCalls);
  log('NETWORK_ATTEMPTS',networkAttempts);
  process.exitCode=2;
}finally{
  if(typeof unregister==='function')try{unregister();}catch{}
  if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
}
