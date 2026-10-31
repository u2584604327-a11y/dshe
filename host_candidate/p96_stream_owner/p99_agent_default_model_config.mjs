/**
 * Safe schema-only inspection of the exact original AgentDefaultModelConfig.
 * No service construction, model, network, prompt, file or user state.
 */
import {AgentDefaultModelConfig} from '@deepseek-ai/dsh-agent-default-model';

const safe=(s)=>/^[A-Za-z_$][A-Za-z0-9_$-]{0,90}$/.test(s);
const schema=AgentDefaultModelConfig.Config;

function primitiveSummary(value){
  if(value===null)return null;
  if(['string','number','boolean'].includes(typeof value))return value;
  if(Array.isArray(value)&&value.length<=30&&value.every(v=>
    v===null||['string','number','boolean'].includes(typeof v)))
    return value;
  return undefined;
}
function shape(value,depth=0){
  if(!value||!['object','function'].includes(typeof value)||depth>3)return null;
  const out={};
  for(const key of Object.keys(value).filter(safe).slice(0,60)){
    const v=value[key];
    const primitive=primitiveSummary(v);
    if(primitive!==undefined){
      out[key]=primitive;
      continue;
    }
    if(key==='dict'&&v&&typeof v==='object'){
      const fields={};
      for(const [field,node] of Object.entries(v).slice(0,30)){
        if(safe(field))fields[field]=shape(node,depth+1);
      }
      out.dict=fields;
      continue;
    }
    if(v&&typeof v==='object'&&['meta','inner','list'].includes(key)){
      out[key]=shape(v,depth+1);
      continue;
    }
    out[key]={type:Array.isArray(v)?'array':typeof v};
  }
  return out;
}
process.stdout.write('P99_AGENT_DEFAULT_MODEL_CONFIG_SCHEMA='+JSON.stringify(shape(schema))+'\n');
process.stdout.write('P99_AGENT_DEFAULT_MODEL_CONFIG_SCHEMA_ONLY=PASS\n');
