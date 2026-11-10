import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Regression for the real Android 2026-11-10 report:
// ReferenceError: fetchJson is not defined -> slot entry crashed in 'main'.
function actualPickerEffect() {
  const source = readFileSync(new URL('../scripts/prepare_official_client.mjs', import.meta.url), 'utf8');
  const prefix = 'one("useConfigPanelStyles();",';
  const from = source.indexOf(prefix);
  assert.ok(from >= 0, 'upstream UI patch anchor must exist');
  const start = from + prefix.length;
  const end = source.indexOf(",'Q_MOBILE_MODEL_HOOK');", start);
  assert.ok(end > start, 'the actual injected hook must be accessible');
  const generated = JSON.parse(source.slice(start, end));
  assert.ok(!generated.includes('fetchJson('), 'no out-of-scope custom fetchJson in the client');
  assert.match(generated, /globalThis\.fetch\(/);
  assert.match(generated, /credentials: "same-origin"/);
  assert.match(generated, /clearTimeout\(qmTimer\)/);
  const beginMarker = '(0, react.useEffect)(() => {';
  const begin = generated.indexOf(beginMarker);
  const finish = generated.indexOf('\n}, []);', begin);
  assert.ok(begin >= 0 && finish > begin, 'bounded model picker React effect exists');
  const body = generated.slice(begin + beginMarker.length, finish);
  return new Function('globalThis', 'setQmModels', 'setQmCatalogStatus', body);
}

test('Android model-picker uses browser fetch, does not crash on successful catalog', async () => {
  const run = actualPickerEffect();
  let cleanup;
  const loaded = new Promise(resolve => {
    cleanup = run({
      fetch: async (url, opts) => {
        assert.equal(url, '/qqbot/q-mobile/models');
        assert.equal(opts.method, 'GET');
        assert.equal(opts.credentials, 'same-origin');
        return { ok: true, json: async () => ({ models: [{provider:'a',id:'b'}], available:true }) };
      }
    }, models => {
      resolve(models);
    }, () => {});
    assert.equal(typeof cleanup, 'function');
  });
  const models = await loaded;
  assert.deepEqual(models, [{provider:'a',id:'b'}]);
  cleanup();
});

test('Android model-picker recovers from unavailable catalog without throwing', async () => {
  const run = actualPickerEffect();
  let cleanup;
  const degraded = new Promise(resolve => {
    cleanup = run({
      fetch: async () => { throw new Error('offline'); }
    }, () => { throw new Error('models should not appear on network failure'); },
    message => resolve(message));
  });
  assert.match(await degraded, /手动配置|官方可点击选项/);
  cleanup();
});

test('packaged client must never reintroduce undefined fetchJson symbol', () => {
  const client = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');
  assert.doesNotMatch(client, /\bfetchJson\s*\(/);
  assert.match(client, /globalThis\.fetch\(/);
});
