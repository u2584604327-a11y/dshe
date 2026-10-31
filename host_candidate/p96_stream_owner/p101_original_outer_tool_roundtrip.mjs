/**
 * P101 original outer Controller to ToolRuntime automatic roundtrip probe.
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
let streamCalls=0,toolExecutions=0,toolNotifications=0,toolRuntimeAttempts=0;
let originalToolExecute=null,observedTools=null,originalAgentStep=null;
let toolRegistration=null;
let selectionCalls=0,saveSelectionCalls=0,workspaceArchiveReads=0,workspaceArchiveSize=null;
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
  constructor(ctx){
    super(ctx,'workspaceRegistry');
    // Fresh isolated P99 workspace has no archived sessions. Test-only
    // peripheral state; never a forged original session or surface event.
    this._archivedSessionIds=Object.freeze([]);
  }
  get archivedSessionIds(){
    workspaceArchiveReads++;
    workspaceArchiveSize=this._archivedSessionIds.length;
    return this._archivedSessionIds;
  }
  _deny(){workspaceAccesses++;throw new Error('P99_WORKSPACE_BOUNDARY_ACCESSED');}
  get(){return this._deny();}
  list(){return this._deny();}
  sessionKnown(){return this._deny();}
  resolveByPath(){return this._deny();}
  bootstrap(){return this._deny();}
}

function safeStackFunctions(error){
  const stack=String(error?.stack||'');
  return stack.split('\n').slice(1,10).map(line=>
    line.match(/at\s+([A-Za-z_$][A-Za-z0-9_$.]{0,100})/)?.[1]||'UNKNOWN'
  );
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
function safeEventMeta(event){
  const data=event&&typeof event==='object'&&event.data&&typeof event.data==='object'
    ?event.data:null;
  const inserted=Array.isArray(data?.inserted)?data.inserted:[];
  return {
    type:String(event?.type??event?.event?.type??'UNKNOWN').slice(0,80),
    topKeys:event&&typeof event==='object'
      ?Object.keys(event).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,25):[],
    dataKeys:data?Object.keys(data)
      .filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,25):[],
    target:typeof data?.target==='string'?data.target.slice(0,40):undefined,
    insertedCount:inserted.length,
    insertedRoles:inserted.map(x=>String(x?.role??'UNKNOWN').slice(0,40)),
    insertedTypes:inserted.map(x=>String(x?.type??'UNKNOWN').slice(0,40)),
    insertedShapes:inserted.map(x=>({
      keys:x&&typeof x==='object'
        ?Object.keys(x).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,25):[],
      surfaceOp:typeof x?.surfaceOp==='string'?x.surfaceOp.slice(0,40):undefined,
      sourceEventSeqsType:Array.isArray(x?.sourceEventSeqs)?'array':typeof x?.sourceEventSeqs,
      sourceEventSeqsCount:Array.isArray(x?.sourceEventSeqs)?x.sourceEventSeqs.length:null,
      sourceType:Array.isArray(x?.source)?'array':typeof x?.source,
      sourceKeys:x?.source&&typeof x.source==='object'
        ?Object.keys(x.source).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,20):[]
    })),
    reasonShape:{
      type:Array.isArray(data?.reason)?'array':typeof data?.reason,
      nullValue:data?.reason===null,
      keys:data?.reason&&typeof data.reason==='object'
        ?Object.keys(data.reason).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,20):[],
      primitive:['string','number','boolean'].includes(typeof data?.reason)
        ?String(data.reason).slice(0,80):undefined,
      kind:typeof data?.reason?.kind==='string'?data.reason.kind.slice(0,60):undefined,
      errorName:typeof data?.reason?.error?.name==='string'
        ?data.reason.error.name.replace(/[^A-Za-z0-9_$-]/g,'').slice(0,60):undefined,
      errorMessage:data?.reason?.error?safeReason(data.reason.error):undefined,
      errorStackFunctions:data?.reason?.error?safeStackFunctions(data.reason.error):[]
    },
    turnShape:{
      type:Array.isArray(data?.turn)?'array':typeof data?.turn,
      nullValue:data?.turn===null,
      primitive:['string','number','boolean'].includes(typeof data?.turn)
        ?String(data.turn).slice(0,80):undefined
    },
    turnKeys:data?.turn&&typeof data.turn==='object'
      ?Object.keys(data.turn).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,20):[]
  };
}
function safeInboxMeta(inbox){
  if(!inbox||typeof inbox!=='object')return {type:typeof inbox,keys:[]};
  const out={type:'object',keys:Object.keys(inbox).slice(0,20)};
  for(const key of ['next-turn','next-step']){
    const items=Array.isArray(inbox[key])?inbox[key]:[];
    out[key]={count:items.length,roles:items.map(x=>String(x?.role??'UNKNOWN').slice(0,40))};
  }
  return out;
}

const ctx=new Context();
let handle=null,configuredOwner=null,unregister=null,disposeSessionObserver=null,originalSessionCommit=null,originalSessionAppend=null;
let promptError=null;
const observedSessionEvents=[];
const observedCommitAttempts=[];
const observedAppendAttempts=[];
const observedListenerTiming=[];
let observerPhase='boot';
let observedSessionIdentity=null;
function safeObservedObject(value){
  if(!value||typeof value!=='object')return {type:typeof value};
  const meta={
    type:'object',
    keys:Object.keys(value).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,30),
    eventType:typeof value.type==='string'?value.type.slice(0,80):undefined,
    seq:typeof value.seq==='number'?value.seq:undefined,
    surfaceOp:typeof value.surfaceOp==='string'?value.surfaceOp.slice(0,40):undefined,
    sourceEventSeqsType:Array.isArray(value.sourceEventSeqs)?'array':typeof value.sourceEventSeqs,
    sourceEventSeqsCount:Array.isArray(value.sourceEventSeqs)?value.sourceEventSeqs.length:null,
    dataKeys:value.data&&typeof value.data==='object'
      ?Object.keys(value.data).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,25):[]
  };
  if(value.event&&typeof value.event==='object'){
    meta.nestedEvent=safeObservedObject(value.event);
  }
  return meta;
}
try{
  // Exact original core.
  await ctx.plugin(AgentRegistry,{});
  await ctx.plugin(SessionStore,{});
  await ctx.plugin(LlmRuntime,{});
  await ctx.plugin(SessionProjectionRegistry,{});
  await ctx.plugin(SystemPrompt,{});
  await ctx.plugin(ToolRuntime,{mode:'native',maxParallelSubCalls:1});
  ctx.on('tools/result',(exec,result)=>{
    if(exec?.name==='read_synthetic_fixture' && exec?.callId==='call_p101_0001' &&
       result?.isError!==true)toolNotifications++;
  });
  observedTools=ctx.get('tools');
  originalToolExecute=observedTools.execute;
  observedTools.execute=function(exec){
    toolRuntimeAttempts++;
    return originalToolExecute.call(this,exec);
  };
  toolRegistration=ctx.get('tools').register({
    name:'read_synthetic_fixture',
    description:'Returns a fixed in-memory string only; no device or external access.',
    parameters:{type:'object',properties:{query:{type:'string'}},
      required:['query'],additionalProperties:false},
    output:{schema:{type:'object',properties:{value:{type:'string'}},
      required:['value'],additionalProperties:false},
      render:()=>[{type:'text',text:'fixture-read-success'}]},
    async execute(args){
      toolExecutions++;
      if(args?.query!=='fixture')throw Error('P101_TOOL_ARGS_UNEXPECTED');
      return {value:'fixture-read-success'};
    }
  });
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
    async resolveModel(provider,model){
      return {
        provider,
        id:model,
        name:'P99 Local Fixture Model',
        description:'Synthetic local metadata only',
        context:{contextWindow:8192},
        inputModalities:['text'],
        systemPromptUpdate:'in-history',
        toolUpdate:'addition-only',
        defaultMaxTokens:128
      };
    },
    async prepareCall(){
      prepareCalls++;
      const model={
        provider:'p99-local',id:'p99-model',name:'P101 Local Fixture Model',
        description:'Synthetic local metadata only',context:{contextWindow:8192},
        inputModalities:['text'],systemPromptUpdate:'in-history',
        toolUpdate:'addition-only',defaultMaxTokens:128
      };
      return {model,stream:async function*(options){
        const defs=Array.isArray(options?.tools)?options.tools:[];
        log('P101_STREAM_OPTION_SHAPE',JSON.stringify({
          keys:options&&typeof options==='object'?Object.keys(options).slice(0,30):[],
          toolsType:Array.isArray(options?.tools)?'array':typeof options?.tools,
          toolsCount:defs.length,
          toolNames:defs.map(x=>String(x?.name??'UNKNOWN').slice(0,60)).slice(0,20),
          messagesCount:Array.isArray(options?.messages)?options.messages.length:null
        }));
        streamCalls++;
        if(streamCalls===1){
          yield {type:'block-start',index:0,blockType:'tool-call'};
          yield {type:'tool-call-delta',index:0,id:'call_p101_0001',
            name:'read_synthetic_fixture',argumentsDelta:'{"query":"fixture"}'};
          yield {type:'block-end',index:0,block:{type:'tool-call',id:'call_p101_0001',name:'read_synthetic_fixture',arguments:{query:'fixture'}}};
          yield {type:'finish',reason:{kind:'tool-call'}};
        }else if(streamCalls===2){
          yield {type:'block-start',index:0,blockType:'text'};
          yield {type:'text-delta',index:0,text:'synthetic continuation complete'};
          yield {type:'block-end',index:0,block:{type:'text',text:'synthetic continuation complete'}};
          yield {type:'finish',reason:{kind:'stop'}};
        }else{
          throw Error('P101_UNEXPECTED_MODEL_STREAM');
        }
      }};
    }
  };
  unregister=llm.registerAdapter(['p99-local'],adapter);
  await llm.resolveModelInfo('p99-local','p99-model',new AbortController().signal);
  log('LOCAL_MODEL_RESOLVED','PASS');

  // Read-only observer for transient original session events, including
  // events that may be rolled back after a fail-closed turn error.
  if(typeof ctx.on==='function'){
    disposeSessionObserver=ctx.on('session/event',(...args)=>{
      observedSessionEvents.push(args.slice(0,5).map(safeObservedObject));
      const [originSession,event]=args;
      observedListenerTiming.push({
        order:observedListenerTiming.length,
        phase:observerPhase,
        argCount:args.length,
        sessionMatchesHandle:observedSessionIdentity===null?'not-yet-created':originSession===observedSessionIdentity,
        originSessionType:typeof originSession,
        eventType:typeof event?.type==='string'?event.type.slice(0,80):typeof event?.type,
        eventSeq:typeof event?.seq==='number'?event.seq:null,
        surfaceOp:typeof event?.surfaceOp==='string'?event.surfaceOp.slice(0,40):null,
        sourceEventSeqsType:Array.isArray(event?.sourceEventSeqs)?'array':typeof event?.sourceEventSeqs,
        sourceEventSeqsCount:Array.isArray(event?.sourceEventSeqs)?event.sourceEventSeqs.length:null,
        stackFunctions:safeStackFunctions(new Error('P100_LISTENER_ONLY')).slice(0,6)
      });
    });
  }

  // Exact original SessionController.
  await ctx.plugin(SessionController,{});
  const controller=ctx.get('sessionController');
  if(!controller||typeof controller.prompt!=='function')
    throw new Error('P99_SESSION_CONTROLLER_NOT_RESOLVED');

  // Exact original configured AgentLoop creation path: AgentOptions must
  // carry provider and model. No manual pi-ai/LlmRuntime call or fake event.
  observerPhase='creating-session';
  configuredOwner=await ctx.get('agentLoop').createAgent(ctx,{
    sessionId:'p99_session_controller_once',
    agentOptions:{provider:'p99-local',model:'p99-model'}
  });
  // The exact original API returns {agent,dispose}; the actual ReactLoopAgent
  // and its SessionStore-backed session are under .agent.
  handle=configuredOwner?.agent;
  if(!handle||typeof configuredOwner?.dispose!=='function')
    throw new Error('P100_ORIGINAL_CREATE_AGENT_WRAPPER_CONTRACT_FAILED');
  observedSessionIdentity=handle?.session;
  const safeLiterals=fn=>{
    if(typeof fn!=='function')return [];
    const src=Function.prototype.toString.call(fn);
    return [...new Set([...src.matchAll(/['"]([A-Za-z][A-Za-z0-9_./:-]{1,70})['"]/g)]
      .map(x=>x[1]))].slice(0,100);
  };
  const agentProto=Object.getPrototypeOf(handle);
  const dispatchProto=handle?.dispatch&&typeof handle.dispatch==='object'
    ?Object.getPrototypeOf(handle.dispatch):null;
  const protoRows=(proto)=>proto?Object.getOwnPropertyNames(proto).filter(x=>
    /^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(x) &&
    typeof Object.getOwnPropertyDescriptor(proto,x)?.value==='function').map(x=>({
      method:x,arity:proto[x].length,literals:safeLiterals(proto[x])
    })).filter(x=>/step|run|tool|dispatch|finish|call|execute|handle|turn|process/i.test(x.method)).slice(0,40):[];
  log('P101_ORIGINAL_AGENT_METHOD_META',JSON.stringify(protoRows(agentProto)));
  const stepSource=Function.prototype.toString.call(agentProto.step);
  const toolBranch=[...stepSource.matchAll(/['"]tool-call['"]/g)].slice(0,8).map(m=>{
    const segment=stepSource.slice(Math.max(0,m.index-400),Math.min(stepSource.length,m.index+400));
    const refs=[...segment.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,64}(?:\??\.[A-Za-z_$][A-Za-z0-9_$]{0,64}){1,5})/g)]
      .map(x=>x[1].replace(/\?\./g,'.'));
    const identifiers=[...segment.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]{0,64})\b/g)]
      .map(x=>x[1]);
    return {propertyPaths:[...new Set(refs)].slice(0,65),
      identifiers:[...new Set(identifiers)].slice(0,100),
      comparisonOperators:[...segment.matchAll(/===|!==|==|!=/g)].map(x=>x[0]).slice(0,25)};
  });
  log('P101_ORIGINAL_STEP_TOOL_BRANCH_META',JSON.stringify(toolBranch));
  log('P101_ORIGINAL_DISPATCH_METHOD_META',JSON.stringify(protoRows(dispatchProto)));
  log('P101_DISPATCH_VALUE_SHAPE',JSON.stringify({
    type:typeof handle.dispatch,
    keys:handle.dispatch&&typeof handle.dispatch==='object'
      ?Object.keys(handle.dispatch).slice(0,30):[]
  }));
  originalAgentStep=handle.step;
  if(typeof originalAgentStep!=='function')throw Error('P101_ORIGINAL_STEP_NOT_CALLABLE');
  handle.step=async function(...args){
    const decision=await originalAgentStep.apply(this,args);
    const keys=decision&&typeof decision==='object'?Object.keys(decision).slice(0,30):[];
    log('P101_ORIGINAL_STEP_DECISION',JSON.stringify({
      kind:typeof decision?.kind==='string'?decision.kind:null,
      type:Array.isArray(decision)?'array':typeof decision,
      keys,
      toolCallsCount:Array.isArray(decision?.toolCalls)?decision.toolCalls.length:null,
      callsCount:Array.isArray(decision?.calls)?decision.calls.length:null
    }));
    return decision;
  };
  observerPhase='session-created';
  const expectedSessionId='p99_session_controller_once';
  const expectedStored=ctx.get('sessions').get(expectedSessionId);
  const safeKeys=x=>x&&typeof x==='object'
    ?Object.keys(x).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,35):[];
  log('CONFIGURED_CREATION_META',JSON.stringify({
    configuredOwnerType:typeof configuredOwner,
    configuredOwnerKeys:safeKeys(configuredOwner),
    configuredOwnerAgentMatchesHandle:configuredOwner?.agent===handle,
    handleType:typeof handle,
    handleKeys:safeKeys(handle),
    handleIdType:typeof handle?.id,
    handleIdEqualsRequested:handle?.id===expectedSessionId,
    handleSessionType:typeof handle?.session,
    handleAgentType:typeof handle?.agent,
    handleAgentKeys:safeKeys(handle?.agent),
    handleHandleKeys:safeKeys(handle?.handle),
    storedByRequestedId:Boolean(expectedStored),
    storedByRequestedMatchesHandleSession:expectedStored===handle?.session,
    innerAgentSessionMatches:expectedStored===handle?.agent?.session
  }));
  const stored=handle?.id===expectedSessionId
    ?ctx.get('sessions').get(handle.id):null;
  if(!stored||stored!==handle.session)
    throw new Error('P99_SESSION_STORE_HANDLE_MISMATCH');

  // Transparent append-entry observer. Records only safe argument metadata,
  // never content. This distinguishes an append that throws before commit
  // from a committed replacement event; original execution is unchanged.
  originalSessionAppend=handle.session.append;
  if(typeof originalSessionAppend!=='function')
    throw new Error('P100_SESSION_APPEND_NOT_CALLABLE');
  handle.session.append=function(type,data,...options){
    const surface=options[0];
    const record={
      eventType:typeof type==='string'?type.slice(0,80):typeof type,
      argCount:2+options.length,
      dataType:Array.isArray(data)?'array':typeof data,
      surfaceOptionsType:Array.isArray(surface)?'array':typeof surface,
      surfaceOptionKeys:surface&&typeof surface==='object'
        ?Object.keys(surface).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,20):[],
      surfaceOp:typeof surface?.surfaceOp==='string'?surface.surfaceOp.slice(0,40):undefined,
      sourceEventSeqsType:Array.isArray(surface?.sourceEventSeqs)?'array':typeof surface?.sourceEventSeqs,
      sourceEventSeqsCount:Array.isArray(surface?.sourceEventSeqs)?surface.sourceEventSeqs.length:null
    };
    observedAppendAttempts.push(record);
    try{
      return originalSessionAppend.call(this,type,data,...options);
    }catch(error){
      record.threw={
        type:String(error?.code||error?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,'').slice(0,80),
        reason:safeReason(error)
      };
      throw error;
    }
  };

  // Transparent diagnostic proxy: capture the exact event before the
  // original Session.commit pipeline and then call the original unchanged.
  // Never mutates event/entry and always rethrows the original error.
  originalSessionCommit=handle.session.commit;
  if(typeof originalSessionCommit!=='function')
    throw new Error('P100_SESSION_COMMIT_NOT_CALLABLE');
  handle.session.commit=function(event,entry){
    const record={
      event:safeObservedObject(event),
      entry:entry&&typeof entry==='object'?{
        type:'object',
        keys:Object.keys(entry).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,30),
        appending:typeof entry.appending==='boolean'?entry.appending:undefined,
        announcing:typeof entry.announcing==='boolean'?entry.announcing:undefined,
        detachRequested:typeof entry.detachRequested==='boolean'?entry.detachRequested:undefined
      }:{type:typeof entry}
    };
    observedCommitAttempts.push(record);
    try{
      return originalSessionCommit.call(this,event,entry);
    }catch(error){
      record.threw={
        type:String(error?.code||error?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,'').slice(0,80),
        reason:safeReason(error)
      };
      throw error;
    }
  };

  const surfaceManager=handle.session?.surfaceManager;
  const projections=surfaceManager?.projections;
  log('SURFACE_MANAGER_META',JSON.stringify({
    type:Array.isArray(surfaceManager)?'array':typeof surfaceManager,
    keys:surfaceManager&&typeof surfaceManager==='object'
      ?Object.keys(surfaceManager).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,30):[],
    constructorName:surfaceManager?.constructor?.name&&/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(surfaceManager.constructor.name)
      ?surfaceManager.constructor.name:null,
    projectionsType:Array.isArray(projections)?'array':typeof projections,
    projectionsCount:Array.isArray(projections)?projections.length:null,
    projectionsConstructor:projections?.constructor?.name&&/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(projections.constructor.name)
      ?projections.constructor.name:null,
    projectionsKeys:projections&&typeof projections==='object'&&!Array.isArray(projections)
      ?Object.keys(projections).filter(k=>/^[A-Za-z_$][A-Za-z0-9_$]{0,64}$/.test(k)).slice(0,20):[]
  }));

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
    observerPhase='prompt-running';
    await Promise.race([
      controller.prompt(request,new AbortController().signal),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('P101_PROMPT_TIMEOUT')),4500))
    ]);
  }catch(e){
    promptError=e;
    log('PROMPT_ERROR_TYPE',String(e?.code||e?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,''));
    log('PROMPT_ERROR_REASON',safeReason(e));
  }

  observerPhase='prompt-settled';
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

  log('OBSERVED_SESSION_EVENT_META',JSON.stringify(observedSessionEvents.slice(-30)));
  log('LISTENER_TIMING_META',JSON.stringify(observedListenerTiming.slice(-30)));
  const listenerArgShapePass=observedListenerTiming.length>0&&
    observedListenerTiming.every(record=>record.sessionMatchesHandle===true&&
      record.argCount>=2&&typeof record.eventType==='string'&&record.eventSeq!==null);
  log('LISTENER_ARGUMENT_SHAPE',listenerArgShapePass?'PASS':'FAIL');
  log('COMMIT_ATTEMPT_META',JSON.stringify(observedCommitAttempts.slice(-30)));
  log('APPEND_ATTEMPT_META',JSON.stringify(observedAppendAttempts.slice(-30)));
  log('AFTER_EVENTS',JSON.stringify(eventShape(afterEvents)));
  const committedDelta=Array.isArray(afterEvents)&&Array.isArray(beforeEvents)
    ?afterEvents.slice(beforeEvents.length):[];
  log('COMMITTED_EVENT_META',JSON.stringify(committedDelta.map(safeEventMeta)));
  log('INBOX_AFTER_META',JSON.stringify(safeInboxMeta(handle.inbox.current())));
  log('PHASE_META',JSON.stringify({
    kind:typeof handle.phase?.kind==='string'?handle.phase.kind:null,
    keys:handle.phase&&typeof handle.phase==='object'?Object.keys(handle.phase).slice(0,20):[],
    lastTurnKeys:handle.phase?.lastTurn&&typeof handle.phase.lastTurn==='object'
      ?Object.keys(handle.phase.lastTurn).slice(0,20):[]
  }));
  log('AFTER_MESSAGE_ROLES',JSON.stringify(afterRoles));
  log('EVENT_COUNT_DELTA',afterCount-beforeCount);
  log('USER_ROLE_DELTA',userDelta);
  log('SELECTION_CALLS',selectionCalls);
  log('SAVE_SELECTION_CALLS',saveSelectionCalls);
  log('MODEL_PREPARE_CALLS',prepareCalls);
  log('WORKSPACE_ACCESSES',workspaceAccesses);
  log('WORKSPACE_ARCHIVE_READS',workspaceArchiveReads);
  log('WORKSPACE_ARCHIVE_IDS_COUNT',workspaceArchiveSize);
  log('NETWORK_ATTEMPTS',networkAttempts);

  const committedUserEvent=committedDelta.some(event=>{
    const data=event&&typeof event==='object'&&event.data&&typeof event.data==='object'
      ?event.data:null;
    const inserted=Array.isArray(data?.inserted)?data.inserted:[];
    return event?.type==='agent/inbox/spliced' &&
      data?.target==='next-turn' &&
      inserted.some(message=>message?.role==='user');
  });
  log('COMMITTED_USER_INBOX_EVENT',committedUserEvent?'PASS':'FAIL');
  log('REAL_SESSION_COMMITTED_USER_TURN',committedUserEvent?'PASS':'FAIL');
  // P101 strict original outer prompt -> model tool call -> original
  // ToolRuntime -> original Session -> automatic second model stream.
  // The harness does not call prepareCall, tools.execute or session.append.
  log('P101_MODEL_PREPARE_CALLS',prepareCalls);
  log('P101_MODEL_STREAM_CALLS',streamCalls);
  log('P101_TOOL_RUNTIME_ATTEMPTS',toolRuntimeAttempts);
  log('P101_TOOL_EXECUTIONS',toolExecutions);
  log('P101_TOOL_NOTIFICATIONS',toolNotifications);
  const toolAppend=observedAppendAttempts.filter(x=>/tool/i.test(x.eventType));
  log('P101_ORIGINAL_TOOL_APPEND_META',JSON.stringify(toolAppend));
  const assistantEvents=committedDelta.filter(x=>x?.type==='assistant/message');
  log('P101_ASSISTANT_BLOCK_META',JSON.stringify(assistantEvents.map(x=>{
    const m=x?.data?.message;
    const blocks=Array.isArray(m?.content)?m.content:[];
    return {
      messageKeys:m&&typeof m==='object'?Object.keys(m).slice(0,30):[],
      contentType:Array.isArray(m?.content)?'array':typeof m?.content,
      blocks:blocks.map(b=>({
        type:typeof b?.type==='string'?b.type:null,
        name:typeof b?.name==='string'?b.name:null,
        idType:typeof b?.id,
        argumentType:typeof b?.arguments,
        keys:b&&typeof b==='object'?Object.keys(b).slice(0,20):[]
      })).slice(0,15),
      streamType:Array.isArray(x?.data?.stream)?'array':typeof x?.data?.stream,
      streamRecords:Array.isArray(x?.data?.stream)?x.data.stream.slice(0,25).map(r=>({
        type:r?.type??null,chunkType:r?.chunk?.type??null,
        finishKind:r?.chunk?.reason?.kind??null,
        keys:r&&typeof r==='object'?Object.keys(r).slice(0,15):[]
      })):[]
    };
  })));
  log('P101_TURN_END_REASONS',JSON.stringify(committedDelta.filter(x=>x?.type==='turn/end')
    .map(x=>({kind:x?.data?.reason?.kind??null,keys:x?.data?.reason&&typeof x.data.reason==='object'
      ?Object.keys(x.data.reason).slice(0,15):[]}))));

  // These are original SessionStore-backed committed events, never harness
  // fabricated tool/call or tool/result entries. Assert exactly-once and
  // verify the result's source sequence points at the actual tool call.
  const committedToolCalls=committedDelta.filter(x=>x?.type==='tool/call');
  const committedToolResults=committedDelta.filter(x=>x?.type==='tool/result');
  const committedTurnEnds=committedDelta.filter(x=>x?.type==='turn/end');
  const resultLinksCall=committedToolCalls.length===1&&committedToolResults.length===1&&
    Array.isArray(committedToolResults[0]?.sourceEventSeqs)&&
    committedToolResults[0].sourceEventSeqs.length===1&&
    committedToolResults[0].sourceEventSeqs[0]===committedToolCalls[0].seq;
  const resultMessage=committedToolResults[0]?.data?.message;
  const resultMessageMatches=resultMessage?.role==='tool'&&
    resultMessage?.callId==='call_p101_0001'&&resultMessage?.isError!==true;
  const firstAssistantCalls=assistantEvents.length===2&&
    assistantEvents[0]?.data?.message?.content?.filter(b=>
      b?.type==='tool-call'&&b?.name==='read_synthetic_fixture'&&
      b?.id==='call_p101_0001').length===1;
  const secondAssistantText=assistantEvents.length===2&&
    assistantEvents[1]?.data?.message?.content?.some(b=>
      b?.type==='text'&&b?.text==='synthetic continuation complete');
  const turnCompletedOnce=committedTurnEnds.length===1&&
    committedTurnEnds[0]?.data?.reason?.kind==='completed';
  log('P101_COMMITTED_TOOL_CALL_COUNT',committedToolCalls.length);
  log('P101_COMMITTED_TOOL_RESULT_COUNT',committedToolResults.length);
  log('P101_RESULT_SOURCE_LINKS_CALL',resultLinksCall?'PASS':'FAIL');
  log('P101_RESULT_MESSAGE_MATCHES',resultMessageMatches?'PASS':'FAIL');
  log('P101_FIRST_ASSISTANT_TOOL_CALL',firstAssistantCalls?'PASS':'FAIL');
  log('P101_SECOND_ASSISTANT_TEXT',secondAssistantText?'PASS':'FAIL');
  log('P101_COMPLETED_TURN_ONCE',turnCompletedOnce?'PASS':'FAIL');
  const p101pass=committedUserEvent&&prepareCalls===2&&streamCalls===2&&
    toolExecutions===1&&toolNotifications===1&&networkAttempts===0&&
    workspaceAccesses===0&&saveSelectionCalls===0&&listenerArgShapePass&&
    resultLinksCall&&resultMessageMatches&&firstAssistantCalls&&
    secondAssistantText&&turnCompletedOnce;
  log('P101_ORIGINAL_AUTOMATIC_TOOL_ROUNDTRIP',p101pass?'PASS':'FAIL');
  log('P101_NO_NETWORK',networkAttempts===0?'PASS':'FAIL');
  if(!p101pass)process.exitCode=2;
}catch(e){
  log('HARNESS_RESULT','BLOCKED_'+String(e?.code||e?.name||'UNKNOWN').replace(/[^A-Za-z0-9_]/g,''));
  log('HARNESS_REASON',safeReason(e));
  log('MODEL_PREPARE_CALLS',prepareCalls);
  log('WORKSPACE_ACCESSES',workspaceAccesses);
  log('NETWORK_ATTEMPTS',networkAttempts);
  process.exitCode=2;
}finally{
  if(handle?.session && typeof originalSessionAppend==='function'){
    try{handle.session.append=originalSessionAppend;}catch{}
  }
  if(handle?.session && typeof originalSessionCommit==='function'){
    try{handle.session.commit=originalSessionCommit;}catch{}
  }
  if(typeof disposeSessionObserver==='function')try{disposeSessionObserver();}catch{}
  if(handle&&typeof originalAgentStep==='function')try{handle.step=originalAgentStep;}catch{}
  if(observedTools&&typeof originalToolExecute==='function')try{observedTools.execute=originalToolExecute;}catch{}
  if(typeof toolRegistration==='function')try{toolRegistration();}catch{}
  if(typeof unregister==='function')try{unregister();}catch{}
  if(configuredOwner&&typeof configuredOwner.dispose==='function'){
    try{await configuredOwner.dispose();}catch{}
  }else if(handle){
    for(const op of ['close','dispose']){
      if(typeof handle[op]==='function'){try{await handle[op]();}catch{}break;}
    }
  }
  if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
}
