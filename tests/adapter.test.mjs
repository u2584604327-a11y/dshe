import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const require=createRequire(import.meta.url);
const local=require('../package.json');
const official=require('@tencent-connect/dsh-qqbot/package.json');
const patch=readFileSync(new URL('../cordis.patch.yml',import.meta.url),'utf8');
const wrapper=readFileSync(new URL('../lib/index.js',import.meta.url),'utf8');

test('core is pinned official 0.5.5 and original Cordis API is delegated',async()=>{
  assert.equal(official.version,'0.5.5');
  assert.equal(official.name,'@tencent-connect/dsh-qqbot');
  assert.equal(local.dependencies['@tencent-connect/dsh-qqbot'],'0.5.5');
  assert.equal(local.dsh.bundle.patch,'./cordis.patch.yml');
  const core=await import('@tencent-connect/dsh-qqbot');
  const adapter=await import('../lib/index.js');
  assert.equal(adapter.name,core.name);
  assert.equal(adapter.Config,core.Config);
  assert.deepEqual(adapter.inject,core.inject);
  await assert.rejects(async()=>adapter.apply(null,{}),/Q_MOBILE_DSH_AGENTS_NOT_AVAILABLE/);
});
test('no custom QQ protocol or credentials interception',()=>{
  assert.ok(wrapper.includes('return official.apply(ctx, config)'));
  assert.ok(!wrapper.includes('WebSocket('));
  assert.ok(!wrapper.includes('QQBOT_SECRET'));
  assert.ok(!wrapper.includes('axios'));
  assert.equal(local.engines.node,'>=20.3.0');
});
test('safe mobile first boot, no embedded credential, no shadow QQ row',()=>{
  assert.match(patch,/id: im-qqbot/);
  assert.match(patch,/name: dsh-qqbot-q-mobile/);
  assert.match(patch,/c2cMode: allowlist/);
  assert.match(patch,/groupMode: open/);
  assert.match(patch,/requireMention: true/);
  assert.match(patch,/restrictPaths: true/);
  assert.match(patch,/maxQueue: 3/);
  assert.match(patch,/appId: __FROM_ENV__/);
  assert.match(patch,/appSecret: __FROM_ENV__/);
  assert.equal((patch.match(/^\s*- id: im-qqbot$/gm)||[]).length,1);
});
test('explicit upstream copyright, non-official and account warning',()=>{
  const notice=readFileSync(new URL('../THIRD_PARTY_NOTICES.md',import.meta.url),'utf8');
  for(const word of ['tencent-connect/dsh-qqbot','Copyright (c) 2026 Tencent Connect','0.5.5','非官方','不保证'])
    assert.ok(notice.includes(word),word);
});
