/**
 * P99 exact-original SessionController one-turn runtime probe.
 *
 * IMPORTANT: this file is intentionally NOT wired into CI until the p99-local
 * LlmRuntime metadata gate passes independently. It preserves original
 * SessionController/SessionCommandController/AgentLoop/Session/Inbox/
 * projections and uses only two explicit fail-closed peripheral test Services:
 * agentDefaultModel selection and workspaceRegistry. Network is denied.
 */
import {Context,Service} from '@deepseek-ai/cordis';
import {AgentRegistry} from '@deepseek-ai/dsh-agent';
import {AgentLoop} from '@deepseek-ai/dsh-agent-loop';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
import {SessionProjectionRegistry} from '@deepseek-ai/dsh-session-projection';
import {SystemPrompt} from '@deepseek-ai/dsh-system-prompt';
import {ToolRuntime} from '@deepseek-ai/dsh-tools';
import {AttachmentStore} from '@deepseek-ai/dsh-attachment';
import {FileUploads} from '@deepseek-ai/dsh-client-file-upload';
import {FileSystem} from '@deepseek-ai/dsh-fs';
import {SessionQueryEngine} from '@deepseek-ai/dsh-session-query';
import {TypertRegistry} from '@deepseek-ai/dsh-typert-registry';
import {CommandRuntime} from '@deepseek-ai/dsh-commands';
import {HostConnectionService} from '@deepseek-ai/dsh-client-connection';
import {RemoteAccessService} from '@deepseek-ai/dsh-api-remote-access';
import {SessionController} from '@deepseek-ai/dsh-api-session-controller';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';

let networkAttempts=0,prepareCalls=0,workspaceAccesses=0;
let selectionCalls=0,saveSelectionCalls=0;
const deny=()=>{networkAttempts++;throw new Error('P99_NETWORK_DENIED');};
globalThis.fetch=deny;
net.Socket.prototype.connect=deny;
net.connect=deny;
net.createConnection=deny;
http.request=deny;
http.get=deny;
https.request=deny;
https.get=deny;

const log=(k,v)=>process.stdout.write('P99_PROMPT_ONCE_'+k+'='+String(v)+'\n');
const safeReason=e=>String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
  .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,200);

class P99AgentDefaultModelBoundary extends Service {
  constructor(ctx){super(ctx,'agentDefaultModel');}
  currentSelection(){
    selectionCalls++;
    return {provider:'p99-local',model:'p99-model'};
  }
  saveSelection(){
    saveSelectionCalls++;
    throw new Error('P99_SAVE_SELECTION_NOT_ALLOWED');
  }
}
class P99WorkspaceBoundary extends Service {
  constructor(ctx){super(ctx,'workspaceRegistry');}
  _deny(){workspaceAccesses++;throw new Error('P99_WORKSPACE_BOUNDARY_ACCESSED');}
  get(){return this._deny();}
  list(){return this._deny();}
  sessionKnown(){return this._deny();}
  resolveByPath(){return this._deny();}
  bootstrap(){return this._deny();}
}

function eventShape(events){
  if(!Array.isArray(events))return {type:typeof events,count:null,types:[]};
  return {
    type:'array',
    count:events.length,
    types:events.slice(-12).map(e=>String(e?.type??e?.event?.type??'UNKNOWN').slice(0,80))
  };
}
function messageRoles(messages){
  if(!Array.isArray(messages))return [];
  return messages.slice(-20).map(m=>String(m?.role??'UNKNOWN').slice(0,40));
}

const ctx=new Context();
let handle=null,unregister=null;
let promptError=null;
try{
  // Exact original core.
  await ctx.plugin(AgentRegistry,{});
  await ctx.plugin(SessionStore,{});
  await ctx.plugin(LlmRuntime,{});
  await ctx.plugin(SessionProjectionRegistry,{});
  await ctx.plugin(SystemPrompt,{});
  await ctx.plugin(ToolRuntime,{mode:'native',maxParallelSubCalls:1});
  await ctx.plugin(AgentLoop,{});

  // Exact original prompt peripherals.
  await ctx.plugin(AttachmentStore,{});
  await ctx.plugin(FileSystem,{});
  await ctx.plugin(SessionQueryEngine,{});
  await ctx.plugin(TypertRegistry,{});
  await ctx.plugin(CommandRuntime,{});
  await ctx.plugin(HostConnectionService,[]);
  await ctx.plugin(RemoteAccessService,{});
  await ctx.plugin(FileUploads,{});

  // Explicit fail-closed test boundaries only.
  await ctx.plugin(P99AgentDefaultModelBoundary,{});
  await ctx.plugin(P99WorkspaceBoundary,{});

  // Exact original LlmRuntime with a local metadata-only adapter.
  const llm=ctx.get('llm');
  const adapter={
    providerInfo(provider){return {id:provider,name:'P99 Local Fixture'};},
    providerRetryPolicy(){return undefined;},
    async resolveModel(model){
      return {
        provider:'p99-local',
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
  await llm.resolveModelInfo('p99-local','p99-model',new AbortController().signal);
  log('LOCAL_MODEL_RESOLVED','PASS');

  // Exact original SessionController.
  await ctx.plugin(SessionController,{});
  const controller=ctx.get('sessionController');
  if(!controller||typeof controller.prompt!=='function')
    throw new Error('P99_SESSION_CONTROLLER_NOT_RESOLVED');

  // Exact original AgentLoop session.
  handle=await ctx.get('agentLoop').create('p99_session_controller_once');
  const stored=ctx.get('sessions').get(handle.id);
  if(!stored||stored!==handle.session)
    throw new Error('P99_SESSION_STORE_HANDLE_MISMATCH');

  const beforeEvents=handle.session.snapshotEvents();
  const beforeMessages=handle.session.deriveMessages();
  log('BEFORE_EVENTS',JSON.stringify(eventShape(beforeEvents)));
  log('BEFORE_MESSAGE_ROLES',JSON.stringify(messageRoles(beforeMessages)));

  const request={
    sessionId:handle.id,
    requestId:'p99-request-0001',
    content:[{type:'text',text:'synthetic safe session-controller turn'}],
    clientTimeZone:'UTC'
  };
  try{
    await Promise.race([
      controller.prompt(request,new AbortController().signal),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('P99_PROMPT_TIMEOUT')),2500))
    ]);
  }catch(e){
    promptError=e;
    log('PROMPT_ERROR_TYPE',String(e?.code||e?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,''));
    log('PROMPT_ERROR_REASON',safeReason(e));
  }

  // Allow only already-scheduled in-memory state propagation.
  await new Promise(resolve=>setTimeout(resolve,30));

  const afterEvents=handle.session.snapshotEvents();
  const afterMessages=handle.session.deriveMessages();
  const beforeCount=Array.isArray(beforeEvents)?beforeEvents.length:-1;
  const afterCount=Array.isArray(afterEvents)?afterEvents.length:-1;
  const beforeRoles=messageRoles(beforeMessages);
  const afterRoles=messageRoles(afterMessages);
  const userDelta=afterRoles.filter(x=>x==='user').length-
    beforeRoles.filter(x=>x==='user').length;

  log('AFTER_EVENTS',JSON.stringify(eventShape(afterEvents)));
  log('AFTER_MESSAGE_ROLES',JSON.stringify(afterRoles));
  log('EVENT_COUNT_DELTA',afterCount-beforeCount);
  log('USER_ROLE_DELTA',userDelta);
  log('SELECTION_CALLS',selectionCalls);
  log('SAVE_SELECTION_CALLS',saveSelectionCalls);
  log('MODEL_PREPARE_CALLS',prepareCalls);
  log('WORKSPACE_ACCESSES',workspaceAccesses);
  log('NETWORK_ATTEMPTS',networkAttempts);

  const committed=afterCount>beforeCount && userDelta>=1;
  log('REAL_SESSION_COMMITTED_USER_TURN',committed?'PASS':'FAIL');
  log('MODEL_WAKEUP_FAIL_CLOSED',prepareCalls<=1?'PASS':'FAIL');
  log('NO_NETWORK',networkAttempts===0?'PASS':'FAIL');
  log('WORKSPACE_UNUSED',workspaceAccesses===0?'PASS':'FAIL');

  if(!committed||networkAttempts!==0||workspaceAccesses!==0||saveSelectionCalls!==0)
    process.exitCode=2;
}catch(e){
  log('HARNESS_RESULT','BLOCKED_'+String(e?.code||e?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,''));
  log('HARNESS_REASON',safeReason(e));
  log('MODEL_PREPARE_CALLS',prepareCalls);
  log('WORKSPACE_ACCESSES',workspaceAccesses);
  log('NETWORK_ATTEMPTS',networkAttempts);
  process.exitCode=2;
}finally{
  if(typeof unregister==='function')try{unregister();}catch{}
  if(handle){
    for(const op of ['close','dispose']){
      if(typeof handle[op]==='function'){try{await handle[op]();}catch{}break;}
    }
  }
  if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
}
