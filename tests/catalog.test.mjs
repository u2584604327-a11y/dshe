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
test('safe mode does not insert an unverified model-picker component', () => {
  const script = readFileSync(new URL('../scripts/prepare_official_client.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(script, /qm-model-picker|Q_MOBILE_MODEL_PICKER|fetchJson/);
  assert.match(script, /SCOPED_LAYOUT|LAZY_SETTINGS_START/);
  const wrapper = readFileSync(new URL('../lib/index.js', import.meta.url), 'utf8');
  assert.doesNotMatch(wrapper, /installModelCatalog|\.\/model-catalog\.js/);
});
test('hung provider never stalls model catalog indefinitely or hides healthy models', async () => {
  const started = Date.now();
  const result = await discoverModels({
    listProviders: () => ['hung', 'healthy'],
    listModels: id => id === 'hung' ? new Promise(() => {}) : ['working-model']
  });
  assert.ok(Date.now() - started < 3000, 'one provider cannot freeze settings');
  assert.deepEqual(result, [{
    provider: 'healthy', id: 'working-model', name: 'working-model'
  }]);
});
test('concurrent optional HTTP requests share a bounded, read-only provider snapshot', async () => {
  let callback, handle, providerCalls = 0, modelCalls = 0;
  const scope = {
    llm: {
      listProviders: async () => { ++providerCalls; return ['local']; },
      listModels: async () => { ++modelCalls; return ['stable']; }
    },
    webServer: { register(spec) { handle = spec.handler; return () => {}; } },
    effect(install) { install(); }
  };
  installModelCatalog({ inject(deps, cb) {
    assert.deepEqual(deps, ['webServer', 'llm']);
    callback = cb;
  }});
  callback(scope);
  assert.equal(typeof handle, 'function');
  const get = async () => {
    let body, status;
    await handle({ method: 'GET', headers: { host: 'dsh.local' } }, {
      writeHead(code) { status = code; },
      end(payload) { body = JSON.parse(payload); }
    });
    assert.equal(status, 200);
    return body.models;
  };
  const all = await Promise.all([get(), get(), get()]);
  assert.ok(all.every(x => x.length === 1 && x[0].id === 'stable'));
  await get();
  assert.equal(providerCalls, 1);
  assert.equal(modelCalls, 1);
});
test('recovery build rejects custom model picker and never waits for QQ binding', () => {
  const script = readFileSync(new URL('../scripts/prepare_official_client.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(script, /qm-model-picker|Q_MOBILE_MODEL_HOOK|fetchJson/);
  assert.match(script, /const inject = \[\];/);
  const wrapper = readFileSync(new URL('../lib/index.js', import.meta.url), 'utf8');
  assert.match(wrapper, /return official\.apply\(ctx, config\)/);
});
