import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const here = new URL('../',import.meta.url);
const read = path=>readFileSync(new URL(path,here),'utf8');
const pkg = JSON.parse(read('package.json'));
const patch = read('cordis.patch.yml');
const wrapper = read('lib/index.js');
const doctor = read('bin/q-mobile-doctor.mjs');

test('v0.1.3 first-install group chat is enabled but still requires real mention',()=>{
  assert.equal(pkg.version,'0.1.5');
  assert.match(patch,/^\s*groupMode: open\s*$/m);
  assert.match(patch,/^\s*requireMention: true\s*$/m);
  assert.match(patch,/^\s*groupAllow: \[\]\s*$/m);
  assert.doesNotMatch(patch,/^\s*groupMode: disabled\s*$/m);
  assert.match(patch,/^\s*c2cMode: allowlist\s*$/m);
  assert.match(patch,/^\s*c2cAllow: \[\]\s*$/m);
});

test('official Tencent QQ SDK, group policy and authentication are delegated unchanged',()=>{
  assert.equal(pkg.dependencies['@tencent-connect/dsh-qqbot'],'0.5.5');
  assert.match(wrapper,/return official\.apply\(ctx, config\)/);
  assert.ok(!wrapper.includes('WebSocket('));
  assert.ok(!wrapper.includes('groupMode'));
  assert.ok(!wrapper.includes('QQBOT_SECRET'));
  assert.equal(pkg.dsh.client.inject.length,0); // don't repeat the web boot hang
  assert.equal(pkg.dsh.client.platform,'web');
  assert.ok(!doctor.includes('writeFile'));
});

test('update will not silently migrate pre-existing group policy or touch saved QQ credentials',()=>{
  const instructions=read('docs/GROUP_CHAT.md');
  assert.match(instructions,/access[.]groupMode.*disabled/);
  assert.match(instructions,/不.*覆.*既有|不会强行覆盖|不会重置/);
  assert.match(instructions,/group OpenID/);
  assert.match(instructions,/bot-ping/);
  assert.match(instructions,/腾讯官方/);
  assert.match(read('README.md'),/群聊仅回复 @机器人的消息/);
});
