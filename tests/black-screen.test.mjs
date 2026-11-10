import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');

test('regression: v0.1.8 generated client is the known-working official settings adapter', () => {
  const client = read('../lib/client.js');
  const generator = read('../scripts/prepare_official_client.mjs');
  for (const source of [client, generator]) {
    assert.doesNotMatch(source, /qm-model-picker|Q_MOBILE_MODEL_PICKER|fetchJson\(/);
    assert.doesNotMatch(source, /Q_MOBILE_MODEL_HOOK|\/qqbot\/q-mobile\/models/);
  }
  assert.match(client, /settings\.section/);
  assert.match(client, /plugins\.detail\.actions/);
  assert.match(client, /QQ 机器人/);
  assert.match(client, /手动填写/);
  assert.match(client, /const inject = \[\]/);
});

test('official settings remain deferred; missing Android slots never crash DSH Web boot', () => {
  const clientSource = read('../lib/client.js');
  let client;
  runInNewContext(clientSource, {
    window: { __ModuleLoader__: {load(info) {
      client = info.factory(() => ({}));
    }}},
    console, setTimeout, clearTimeout
  });
  assert.ok(client);
  assert.deepEqual(Array.from(client.inject), []);
  assert.doesNotThrow(() => client.apply({inject() { throw Error('no slots'); }}));
});

test('no additional model service is injected into official QQ runtime', () => {
  const wrapper = read('../lib/index.js');
  assert.doesNotMatch(wrapper, /installModelCatalog|model-catalog\.js/);
  const pkg = JSON.parse(read('../package.json'));
  assert.equal(pkg.version, '0.1.8');
  assert.equal(pkg.dependencies['@tencent-connect/dsh-qqbot'], '0.5.5');
  assert.ok(!pkg.files.includes('lib/model-catalog.js'));
});
