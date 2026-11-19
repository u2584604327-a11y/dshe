/**
 * Safe constructor contracts for exact original SessionController peripherals.
 * Import/reflection only; no construction, plugin, prompt, model, network/tool.
 */
import {AgentDefaultModelConfig} from '@deepseek-ai/dsh-agent-default-model';
import {FileUploads} from '@deepseek-ai/dsh-client-file-upload';
import {WorkspaceRegistry} from '@deepseek-ai/dsh-workspace';
import {HostConnectionService} from '@deepseek-ai/dsh-client-connection';
import {DomainFacility} from '@deepseek-ai/dsh-storage-domain';

const safe=s=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);

function extractConstructor(src){
  const m=/constructor\s*\(([^)]{0,500})\)\s*\{/.exec(src);
  if(!m)return {params:[],fields:[],memberCalls:[],safeLiterals:[],sourceSize:0};
  const params=m[1].split(',').map(x=>x.trim()).filter(safe).slice(0,12);
  const open=src.indexOf('{',m.index+m[0].length-1);
  let depth=0,quote=null,esc=false,end=-1;
  for(let i=open;i<src.length;i++){
    const ch=src[i];
    if(quote){
      if(esc){esc=false;continue;}
      if(ch==='\\'){esc=true;continue;}
      if(ch===quote)quote=null;
      continue;
    }
    if(ch==="'"||ch==='""'||ch==='`'){quote=ch;continue;}
    if(ch==='{')depth++;
    else if(ch==='}'&&--depth===0){end=i;break;}
  }
  const body=end>open?src.slice(open+1,end):'';
  const fields=[...body.matchAll(/this\??\.([A-Za-z_$][A-Za-z0-9_$]{0,90})/g)]
    .map(x=>x[1]).filter(safe);
  const memberCalls=[...body.matchAll(/([A-Za-z_$][A-Za-z0-9_$]{0,90}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,90}){1,5})\s*\(/g)]
    .map(x=>x[1]).filter(x=>x.split('.').every(safe));
  const literals=[...body.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
    .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
  return {
    params,
    fields:[...new Set(fields)].slice(0,40),
    memberCalls:[...new Set(memberCalls)].slice(0,60),
    safeLiterals:[...new Set(literals)].slice(0,40),
    sourceSize:body.length
  };
}
for(const [name,Class] of [
  ['AgentDefaultModelConfig',AgentDefaultModelConfig],
  ['FileUploads',FileUploads],
  ['WorkspaceRegistry',WorkspaceRegistry],
  ['HostConnectionService',HostConnectionService],
  ['DomainFacility',DomainFacility],
]){
  process.stdout.write('P99_PERIPHERAL_CONSTRUCTOR='+JSON.stringify({
    name,arity:Class.length,contract:extractConstructor(Function.prototype.toString.call(Class))
  })+'\n');
}
process.stdout.write('P99_PERIPHERAL_CONSTRUCTOR_REFLECTION_ONLY=PASS\n');
