import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { discoverModels, catalogHandler, installModelCatalog } from '../lib/model-catalog.js';

test('provider/model list comes exclusively from registered DSH LLM service', async()=>{
  const models=await discoverModels({
    listProviders:()=>[{id:'host-provider'}, {id:'broken-provider'}],
    listModels:async id=> {
      if(id==='broken-provider')throw Error('provider offline');
      return [{id:'small',name:'Lightweight'}, {id:'small'}, {id:'<unsafe>'}];
    }
  });
  assert.deepEqual(models,[{provider:'host-provider',id:'small',name:'Lightweight'}]);
  assert.deepEqual(await discoverModels(null),[]);
});
test('read-only model endpoint rejects POST and cross-site origins',async()=>{
  const llm={listProviders:()=>['local'],listModels:async()=>[{id:'local-model'}]};
  async function call(method,origin) {
    const response={};
    await catalogHandler({method,headers:{host:'dsh.local',...(origin?{origin}:{})}},{
      writeHead(status,headers){response.status=status;response.headers=headers},
      end(body){response.body=JSON.parse(body)}
    },llm);
    return response;
  }
  assert.equal((await call('POST')).status,405);
  assert.equal((await call('GET','https://attacker.local')).status,403);
  const ok=await call('GET','https://dsh.local');
  assert.equal(ok.status,200);
  assert.deepEqual(ok.body.models,[{provider:'local',id:'local-model',name:'local-model'}]);
  assert.equal(ok.headers['cache-control'],'no-store');
});
test('unavailable runtime services must not block official QQ boot',()=>{
  assert.equal(installModelCatalog({}),false);
  assert.equal(installModelCatalog({inject(){throw Error('not yet available')}}),false);
  const requests=[];
  assert.equal(installModelCatalog({inject(deps,callback){requests.push(deps);}}),true);
  assert.deepEqual(requests,[['webServer','llm']]);
});
test('official client includes both model picker and nonblocking settings integration',()=>{
  const client=readFileSync(new URL('../lib/client.js',import.meta.url),'utf8');
  assert.match(client,/qm-model-picker/);
  assert.match(client,/qqbot\/q-mobile\/models/);
  assert.match(client,/const inject = \[\]/);
  assert.match(client,/ctx\.inject\(\["slots"\]/);
});
