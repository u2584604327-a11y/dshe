import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const patch=readFileSync(new URL('../cordis.patch.yml',import.meta.url),'utf8');
const readme=readFileSync(new URL('../README.md',import.meta.url),'utf8');
test('new QQ installs have bounded group background and safe tone defaults',()=>{
 assert.match(patch,/historyLimit:\s*3/);
 assert.match(patch,/sessionIdleTimeout:\s*720000/);
 assert.match(patch,/requireMention:\s*true/);
 assert.match(patch,/groupMode:\s*open/);
 assert.match(patch,/c2cMode:\s*allowlist/);
 assert.match(patch,/groupPrompt:/);
 assert.match(patch,/directPrompt:/);
});
test('documentation distinguishes buffered history from persistent DSH memory',()=>{
 assert.match(readme,/NOT a hard cap|NOT a hard/);
 assert.match(readme,/\/model/);
 assert.match(readme,/\/compact/);
 assert.match(readme,/\/new/);
});
