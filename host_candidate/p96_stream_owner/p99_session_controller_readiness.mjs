/**
 * Exact original SessionController construction readiness probe.
 * Attaches exact original services wherever they can boot safely. Two clearly
 * marked fail-closed boundary Services exist only to satisfy unused construction
 * injection keys: agentDefaultModel and storageDomain. They throw if accessed.
 * No session turn/prompt/model/tool/browser/Android/user data/file write.
 */
import {Context,Service} from '@deepseek-ai/cordis';
import {AgentRegistry} from '@deepseek-ai/dsh-agent';
import {SessionStore} from '@deepseek-ai/dsh-session';
import {LlmRuntime} from '@deepseek-ai/dsh-llm';
import {SessionProjectionRegistry} from '@deepseek-ai/dsh-session-projection';
import {AttachmentStore} from '@deepseek-ai/dsh-attachment';
import {CommandRuntime} from '@deepseek-ai/dsh-commands';
import {HostConnectionService} from '@deepseek-ai/dsh-client-connection';
import {FileUploads} from '@deepseek-ai/dsh-client-file-upload';
import {FileSystem} from '@deepseek-ai/dsh-fs';
import {SessionQueryEngine} from '@deepseek-ai/dsh-session-query';
import {SessionPersistence} from '@deepseek-ai/dsh-session-persistence';
import {TypertRegistry} from '@deepseek-ai/dsh-typert-registry';
import {WorkspaceRegistry} from '@deepseek-ai/dsh-workspace';
import {SessionController} from '@deepseek-ai/dsh-api-session-controller';
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

const log=(k,v)=>process.stdout.write('P99_CONTROLLER_READY_'+k+'='+String(v)+'\n');
const safeReason=e=>String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
  .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,180);
const ctx=new Context();
const attached=[];
let adapterAccesses=0;

class P99AgentDefaultModelBoundary extends Service {
  constructor(innerCtx){super(innerCtx,'agentDefaultModel');}
  currentSelection(){adapterAccesses++;throw new Error('P99_AGENT_DEFAULT_MODEL_BOUNDARY_ACCESSED');}
  saveSelection(){adapterAccesses++;throw new Error('P99_AGENT_DEFAULT_MODEL_BOUNDARY_ACCESSED');}
}
class P99StorageDomainBoundary extends Service {
  constructor(innerCtx){super(innerCtx,'storageDomain');}
  open(){adapterAccesses++;throw new Error('P99_STORAGE_DOMAIN_BOUNDARY_ACCESSED');}
  get(){adapterAccesses++;throw new Error('P99_STORAGE_DOMAIN_BOUNDARY_ACCESSED');}
}


async function attach(label,Class,config={}){
  try{
    await Promise.race([
      ctx.plugin(Class,config),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('PLUGIN_TIMEOUT')),650))
    ]);
    attached.push(label);
    log('PLUGIN_'+label,JSON.stringify({status:'ATTACHED'}));
    return true;
  }catch(e){
    log('PLUGIN_'+label,JSON.stringify({
      status:'BLOCKED',error:String(e?.code||e?.name||'UNKNOWN'),reason:safeReason(e)
    }));
    return false;
  }
}
function serviceType(name){
  try{return typeof ctx.get(name);}catch{return 'GET_ERROR';}
}

try{
  await attach('AGENTS',AgentRegistry);
  await attach('SESSIONS',SessionStore);
  await attach('LLM',LlmRuntime);
  await attach('SESSION_PROJECTIONS',SessionProjectionRegistry);
  await attach('AGENT_DEFAULT_MODEL_BOUNDARY',P99AgentDefaultModelBoundary);
  await attach('ATTACHMENTS',AttachmentStore);
  await attach('FS',FileSystem);
  await attach('SESSION_QUERY',SessionQueryEngine);
  await attach('TYPERT_REGISTRY',TypertRegistry);
  await attach('COMMANDS',CommandRuntime);
  await attach('CONNECTION',HostConnectionService,[]);

  try{
    const remote=await import('@deepseek-ai/dsh-api-remote-access');
    const RemoteClass=typeof remote.default==='function'?remote.default:
      Object.values(remote).find(v=>typeof v==='function'&&Array.isArray(v.inject));
    if(RemoteClass)await attach('REMOTE_ACCESS',RemoteClass);
    else log('PLUGIN_REMOTE_ACCESS',JSON.stringify({status:'NO_CLASS'}));
  }catch(e){
    log('PLUGIN_REMOTE_ACCESS',JSON.stringify({
      status:'IMPORT_BLOCKED',error:String(e?.code||e?.name||'UNKNOWN'),reason:safeReason(e)
    }));
  }

  await attach('FILE_UPLOADS',FileUploads);
  await attach('SESSION_PERSISTENCE',SessionPersistence);
  await attach('STORAGE_DOMAIN_BOUNDARY',P99StorageDomainBoundary);
  await attach('WORKSPACE_REGISTRY',WorkspaceRegistry);

  const inject=Array.isArray(SessionController.inject)?SessionController.inject:[];
  const serviceTypes={};
  const missing=[];
  for(const name of inject){
    const type=serviceType(name);
    serviceTypes[name]=type;
    if(type==='undefined'||type==='GET_ERROR')missing.push(name);
  }
  log('INJECT_KEYS',JSON.stringify(inject));
  log('SERVICE_TYPES',JSON.stringify(serviceTypes));
  log('MISSING_BEFORE_CONTROLLER',JSON.stringify(missing));
  log('ATTACHED_CLASSES',JSON.stringify(attached));

  if(missing.length===0){
    const ok=await attach('SESSION_CONTROLLER',SessionController);
    log('SESSION_CONTROLLER_SERVICE_TYPE',serviceType('sessionController'));
    log('SESSION_CONTROLLER_CONSTRUCTED',ok?'PASS':'BLOCKED');
  }else{
    log('SESSION_CONTROLLER_CONSTRUCTED','NOT_ATTEMPTED_MISSING_DEPENDENCIES');
  }
  log('ADAPTER_ACCESSES',adapterAccesses);
  log('NETWORK_ATTEMPTS',networkAttempts);
  log('NO_PROMPT_NO_MODEL_NO_TOOL','PASS');
  if(networkAttempts!==0||adapterAccesses!==0)process.exitCode=2;
}finally{
  if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
}
