import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { PICKER_SOURCE } from '../scripts/optional-model-picker.mjs';

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');

test('generated client keeps stable official settings and mounts isolated picker only as a child', () => {
  const client = read('../lib/client.js');
  const generator = read('../scripts/prepare_official_client.mjs');
  assert.match(client, /settings\.section/);
  assert.match(client, /plugins\.detail\.actions/);
  assert.match(client, /QQ 机器人/);
  assert.match(client, /手动填写/);
  assert.match(client, /const inject = \[\]/);
  assert.match(client, /function QMobilePicker/);
  assert.match(client, /QMobilePicker, \{ form, patch \}/);
  assert.ok(!client.includes('fetchJson("/qqbot/q-mobile/models"'));
  assert.match(generator, /Q_MOBILE_ISOLATED_PICKER/);
  assert.ok(!generator.includes('Q_MOBILE_MODEL_HOOK'));
});

test('mobile DSH startup does not depend on the optional model service or React rendering', () => {
  let client;
  runInNewContext(read('../lib/client.js'), {
    window:{ __ModuleLoader__:{ load(info) { client = info.factory(() => ({})); } } },
    console, setTimeout, clearTimeout
  });
  assert.ok(client);
  assert.deepEqual(Array.from(client.inject), []);
  assert.doesNotThrow(() => client.apply({inject() { throw Error('no optional slots'); }}));
});

function modelPickerHarness(fetchImpl) {
  const values = [], setters = [], effects = [];
  let cursor = 0;
  const react = {
    useState(value) {
      const at = cursor++;
      if (!(at in values)) values[at] = value;
      const setter = next => { values[at] = typeof next === 'function' ? next(values[at]) : next; };
      setters[at] = setter;
      return [values[at], setter];
    },
    useRef(value) {
      const at = cursor++;
      if (!(at in values)) values[at] = {current:value};
      return values[at];
    },
    useEffect(callback) { effects.push(callback); },
    createElement(name, props, ...children) { return {name, props:props||{}, children}; }
  };
  const Picker = runInNewContext(PICKER_SOURCE + '\nQMobilePicker', {
    react, console,
    globalThis:{fetch:fetchImpl}, AbortController, setTimeout, clearTimeout, Promise, Error
  });
  function render(form, patch) { cursor = 0; return Picker({form,patch}); }
  function find(node, name) {
    if (!node || typeof node !== 'object') return null;
    if (node.name === name) return node;
    for (const child of node.children||[]) {
      const result = find(child,name);
      if (result) return result;
    }
    return null;
  }
  return {render,find,values,effects};
}

test('model choices populate on button click only and patch both official fields', async () => {
  let fetched = 0;
  const h = modelPickerHarness(async (_url, options) => {
    fetched++;
    assert.equal(options.method,'GET');
    assert.equal(options.credentials,'same-origin');
    return {ok:true, json:async () => ({available:true,models:[
      {provider:'host',id:'fast',name:'Fast'},
      {provider:'host',id:'slow',name:'Slow'}
    ]})};
  });
  const form = {provider:'',model:''};
  const patch = (key,value) => {form[key] = value;};
  let tree = h.render(form,patch);
  assert.equal(fetched,0, 'must not fetch during DSH or QQ settings boot');
  h.find(tree,'button').props.onClick();
  await new Promise(resolve => setTimeout(resolve,20));
  assert.equal(fetched,1);
  tree = h.render(form,patch);
  const select = h.find(tree,'select');
  const values = select.children.flat().filter(Boolean).map(option=>option.props.value);
  assert.ok(values.includes(JSON.stringify(['host','fast'])));
  select.props.onChange({target:{value:JSON.stringify(['host','fast'])}});
  assert.deepEqual(form,{provider:'host',model:'fast'});
});

test('offline catalog degrades without changing saved model or crashing the page', async () => {
  const h = modelPickerHarness(async () => {throw Error('offline');});
  const form = {provider:'saved-provider',model:'existing'};
  let tree = h.render(form,()=>{ throw Error('should not modify model on GET failure');});
  h.find(tree,'button').props.onClick();
  await new Promise(resolve => setTimeout(resolve,20));
  tree = h.render(form,()=>{});
  assert.ok(h.find(tree,'select'));
  assert.ok(tree.children.flat().some(x=>x?.name==='p' && String(x.children).includes('/model')));
  assert.deepEqual(form,{provider:'saved-provider',model:'existing'});
});

test('packaged runtime preserves official Tencent QQ SDK and no custom send hooks',()=>{
  const pkg = JSON.parse(read('../package.json'));
  const wrapper = read('../lib/index.js');
  assert.equal(pkg.version,'0.1.9');
  assert.equal(pkg.dependencies['@tencent-connect/dsh-qqbot'],'0.5.5');
  assert.match(wrapper, /return official\.apply\(ctx, config\)/);
  assert.doesNotMatch(wrapper, /WebSocket\(|sendMessage\(|replyMessage\(/);
});
