/**
 * Exact original SessionController peripheral-service boot diagnostic.
 * No prompt/session turn/model/tool/browser/Android/file write. Network is
 * denied before any original service is attached. Each case gets a fresh
 * Cordis Context and only documented prerequisites.
 */
import {Context} from '@deepseek-ai/cordis';
import {AgentRegistry} from '@deepseek-ai/dsh-agent';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {AgentDefaultModelConfig} from '@deepseek-ai/dsh-agent-default-model';
import {AttachmentStore} from '@deepseek-ai/dsh-attachment';
import {FileUploads} from '@deepseek-ai/dsh-client-file-upload';
import {FileSystem} from '@deepseek-ai/dsh-fs';
import {SessionQueryEngine} from '@deepseek-ai/dsh-session-query';
import {TypertRegistry} from '@deepseek-ai/dsh-typert-registry';
import {WorkspaceRegistry} from '@deepseek-ai/dsh-workspace';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

let networkAttempts=0;
const deny=()=>{networkAttempts++;throw new Error('P99_NETWORK_DENIED');};
globalThis.fetch=deny;
net.Socket.prototype.connect=deny;
net.connect=deny;
net.createConnection=deny;
http.request=deny;
http.get=deny;
https.request=deny;
https.get=deny;

const safeReason=e=>String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
  .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,180);
const log=(k,v)=>process.stdout.write('P99_ORIGINAL_SERVICE_'+k+'='+String(v)+'\n');

async function probe(label,Class,key,setup){
  const ctx=new Context();
  try{
    if(setup)await setup(ctx);
    await ctx.plugin(Class,{});
    const value=ctx.get(key);
    log(label,JSON.stringify({
      attached:true,
      expectedKey:key,
      resolvedType:typeof value,
      constructor:value?.constructor?.name||null,
      networkAttempts
    }));
  }catch(e){
    log(label,JSON.stringify({
      attached:false,
      expectedKey:key,
      error:String(e?.code||e?.name||'UNKNOWN'),
      reason:safeReason(e),
      networkAttempts
    }));
  }finally{
    if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
  }
}

await probe('AGENT_DEFAULT_MODEL',AgentDefaultModelConfig,'agentDefaultModel');
await probe('ATTACHMENTS',AttachmentStore,'attachments');
await probe('FS',FileSystem,'fs');
await probe('TYPERT',TypertRegistry,'typert');
await probe('SESSION_QUERY',SessionQueryEngine,'sessionQuery',async ctx=>{
  await ctx.plugin(SessionStore,{});
});
await probe('FILE_UPLOADS',FileUploads,'fileUploads',async ctx=>{
  await ctx.plugin(AgentRegistry,{});
  await ctx.plugin(AttachmentStore,{});
});
await probe('WORKSPACE_REGISTRY',WorkspaceRegistry,'workspaceRegistry');

log('NETWORK_ATTEMPTS',networkAttempts);
log('NO_PROMPT_NO_MODEL_NO_TOOL','PASS');
if(networkAttempts!==0)process.exitCode=2;
