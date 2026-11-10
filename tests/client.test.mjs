import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';

const code=readFileSync(new URL('../lib/client.js',import.meta.url),'utf8');
const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));
function loadOfficialClient(){
  let id,client;
  const sandbox={
    window:{__ModuleLoader__:{load(value){
      id=value.id;
      client=value.factory(name=>{
        if(name==='react')return {};
        throw Error('UNKNOWN_BROWSER_REQUIRE_'+name);
      });
    }}},
    console,
    setTimeout,clearTimeout
  };
  runInNewContext(code,sandbox);
  return {id,client};
}
test('bundle contains official QR/settings and Tencent copyright',()=>{
  assert.equal(pkg.version,'0.1.6');
  assert.equal(pkg.exports['./client'],'./lib/client.js');
  assert.equal(pkg.dsh.client.platform,'web');
  assert.deepEqual(pkg.dsh.client.inject,[]);
  assert.equal(pkg.dependencies['@tencent-connect/dsh-qqbot'],'0.5.5');
  assert.ok(pkg.files.includes('lib/client.js'));
  assert.ok(pkg.files.includes('THIRD_PARTY_LICENSE_TENCENT.txt'));
  assert.match(code,/id: "dsh-qqbot-q-mobile"/);
  assert.match(code,/const PACKAGE_NAME = "dsh-qqbot-q-mobile"/);
  assert.match(code,/const inject = \[\]/);
  assert.match(code,/\/qqbot\/im-qqbot\/bind\/refresh/);
  assert.match(code,/\/qqbot\/im-qqbot\/bind\/manual/);
  assert.match(code,/settings\.section/);
  assert.match(code,/plugins\.detail\.actions/);
  assert.match(code,/QQ 机器人/);
  assert.match(code,/手动填写/);
  assert.ok(!code.includes('id: "@tencent-connect/dsh-qqbot"'));
});
test('MISSING slots at startup does NOT block DSH web boot',()=>{
  const {id,client}=loadOfficialClient();
  assert.equal(id,'dsh-qqbot-q-mobile');
  assert.equal(client.name,'im-qqbot-client');
  assert.deepEqual(Array.from(client.inject),[]);
  const requests=[];
  let installSlots;
  const outer=new Proxy({
    inject(deps,callback){
      requests.push(Array.from(deps));
      installSlots=callback;
    }
  },{get(target,key){
    if(['slots','sidebarRight','sidebarRightTabs'].includes(key))
      throw Error('cannot get property '+String(key)+' without inject');
    return target[key];
  }});
  assert.doesNotThrow(()=>client.apply(outer));
  assert.deepEqual(requests,[['slots']]);
  assert.equal(typeof installSlots,'function');
  // No UI services were registered. Web boot is not waiting for slots.
});
test('DEFERRED real slots service registers QQ settings + plugin-detail action',()=>{
  const {client}=loadOfficialClient();
  let installSlots;
  const registered=[],delayed=[];
  client.apply({inject(deps,fn){
    assert.deepEqual(Array.from(deps),['slots']);
    installSlots=fn;
  }});
  assert.equal(registered.length,0);
  assert.equal(typeof installSlots,'function');
  const slots={
    inject(_name,handler){
      const result=handler();
      return typeof result==='function'?result:()=>{};
    },
    register(spec,component){
      registered.push({spec,component});
      return ()=>{};
    }
  };
  const scope={
    slots,
    effect(){},
    inject(deps,fn){
      const list=Array.from(deps);
      if(list.length===2 && list[0]==='sidebarRight' && list[1]==='sidebarRightTabs'){
        // Android can legitimately omit both desktop sidebar services.
        delayed.push({kind:'sidebar',callback:fn});
        return;
      }
      if(list.length===1 && list[0]==='layout'){
        fn({slots,layout:{selectPanel(){}}});
        return;
      }
      throw Error('UNKNOWN_INJECT_'+list.join(','));
    }
  };
  assert.doesNotThrow(()=>installSlots(scope));
  const settings=registered.find(x=>x.spec.name==='settings.section');
  assert.equal(settings.spec.id,'qqbot');
  assert.equal(settings.spec.label,'QQ 机器人');
  assert.equal(typeof settings.component,'function');
  assert.ok(registered.some(x=>x.spec.name==='plugins.detail.actions'));
  assert.ok(registered.some(x=>x.spec.name==='main'));
  assert.ok(registered.some(x=>x.spec.name==='sidebar.panellist'));
  assert.equal(delayed.length,1); // Optional, must NOT hold settings hostage
});
test('missing injection implementation and missing slots are fail-open for APP boot',()=>{
  const {client}=loadOfficialClient();
  assert.doesNotThrow(()=>client.apply({}));
  assert.doesNotThrow(()=>client.apply({inject(){throw Error('host temporarily unavailable')}}));
});
test('official MIT license and nonofficial derivative attribution packaged',()=>{
  const license=readFileSync(new URL('../THIRD_PARTY_LICENSE_TENCENT.txt',import.meta.url),'utf8');
  assert.match(license,/MIT License/);
  assert.match(license,/Copyright \(c\) 2026 Tencent Connect/);
  const notices=readFileSync(new URL('../THIRD_PARTY_NOTICES.md',import.meta.url),'utf8');
  assert.match(notices,/非官方/);
  assert.match(notices,/v0\.1\.2/);
});
