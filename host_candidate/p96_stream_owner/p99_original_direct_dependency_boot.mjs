/**
 * Exact original direct dependency boot diagnostic for fileUploads/workspace.
 * No prompt/session/model/tool/network/user data or file write.
 */
import {Context} from '@deepseek-ai/cordis';
import {CommandRuntime} from '@deepseek-ai/dsh-commands';
import * as Connection from '@deepseek-ai/dsh-client-connection';
import * as StorageDomain from '@deepseek-ai/dsh-storage-domain';
import {SessionPersistence} from '@deepseek-ai/dsh-session-persistence';
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

const log=(k,v)=>process.stdout.write('P99_DIRECT_DEP_'+k+'='+String(v)+'\n');
const reason=e=>String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
  .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,200);

async function probe(label,plugin,key,config={}){
  const ctx=new Context();
  try{
    await Promise.race([
      ctx.plugin(plugin,config),
      new Promise((_,reject)=>setTimeout(()=>reject(new Error('PLUGIN_TIMEOUT')),1800))
    ]);
    const value=ctx.get(key);
    log(label,JSON.stringify({
      attached:true,key,resolvedType:typeof value,
      constructor:value?.constructor?.name||null,networkAttempts
    }));
  }catch(e){
    log(label,JSON.stringify({
      attached:false,key,error:String(e?.code||e?.name||'UNKNOWN'),
      reason:reason(e),networkAttempts
    }));
  }finally{
    if(typeof ctx.dispose==='function')try{await ctx.dispose();}catch{}
  }
}

await probe('COMMAND_RUNTIME',CommandRuntime,'commands');
if(typeof Connection.HostConnectionService==='function')
  await probe('CONNECTION_CLASS',Connection.HostConnectionService,'connection');
if(typeof Connection.apply==='function')
  await probe('CONNECTION_APPLY',Connection.apply,'connection');
if(typeof StorageDomain.DomainFacility==='function')
  await probe('STORAGE_DOMAIN_CLASS',StorageDomain.DomainFacility,'storageDomain');
if(typeof StorageDomain.apply==='function')
  await probe('STORAGE_DOMAIN_APPLY',StorageDomain.apply,'storageDomain');
await probe('SESSION_PERSISTENCE',SessionPersistence,'sessionPersistence');

log('NETWORK_ATTEMPTS',networkAttempts);
log('NO_PROMPT_NO_MODEL_NO_TOOL','PASS');
if(networkAttempts!==0)process.exitCode=2;
