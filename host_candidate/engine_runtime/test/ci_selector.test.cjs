const assert = require('node:assert/strict');
const select = require('../../../.github/scripts/pr80_targeted_ci.cjs');
const head = 'a'.repeat(40), before = 'b'.repeat(40);
const branch = 'dsh/p96-original-engine-stream-owner-narrow-20261030';
const context = {repo: {owner: 'u2584604327-a11y', repo: 'dshe'}, runId: 99,
  payload: {action: 'synchronize', before, after: head, pull_request: {
    number: 80, head: {sha: head, ref: branch, repo: {full_name: 'u2584604327-a11y/dshe'}}}}};
function run(id, filename, extra = {}) {return {id, path: '.github/workflows/' + filename,
  head_sha: head, head_branch: branch, event: 'pull_request', status: 'queued', pull_requests: [{number: 80}], ...extra};}
async function check(changed, runs, event = context, current = head, cancelEffect = () => {}) {
  const cancelled = [];
  const github = {rest: {pulls: {get: async () => ({data: {head: {sha: current}}})},
    repos: {compareCommitsWithBasehead: async () => ({data: {status: 'ahead', files: changed.map(filename => ({filename}))}})},
    actions: {listWorkflowRunsForRepo() {}, cancelWorkflowRun: async request => {
      assert.equal(request.owner, 'u2584604327-a11y');assert.equal(request.repo, 'dshe');cancelled.push(request.run_id);
      assert.equal(request.request.timeout,2500);assert.equal(request.request.retries,0);await cancelEffect();
    }}}, paginate: async () => runs};
  const core = {info() {}, warning() {}, summary: {addRaw() {return this;}, async write() {}}};
  await select({github, context: event, core});return cancelled;
}
(async () => {
  const filename = 'p310-original-art-verify-one-shot.yml';
  const runs = [run(1, filename), run(2, 'p139-p51-arm64-sidecar-test-apk-artifact.yml'),
    run(3, filename, {head_sha: before}), run(4, filename, {pull_requests: [{number: 81}]}),
    run(5, filename, {pull_requests: []}), run(6, filename, {pull_requests: [{number: 80}, {number: 81}]}),
    run(7, filename, {head_branch: 'other'}), run(8, filename, {status: 'completed'}),
    run(9, 'p134-real-arm64-isolated-guard.yml'), run(10, 'p245-build-only-probe.yml'),
    run(11, 'engine-runtime-http.yml')];
  const first = await check(['host_candidate/engine_runtime/http_transport.mjs'], runs);
  assert.deepEqual(first, [1, 9]);
  const dex = await check(['host_candidate/p245_build_only_probe/strict_dex.py'], runs);
  assert.deepEqual(dex, [9]);
  assert.deepEqual(await check(['README.md'], runs, context, before), []);
  const other = structuredClone(context);other.payload.pull_request.number = 81;
  assert.deepEqual(await check(['README.md'], runs, other), []);
  const labeled = structuredClone(context);labeled.payload.action = 'labeled';
  assert.deepEqual(await check(['README.md'], runs, labeled), []);
  const realNow=Date.now;let now=0;
  try{
    Date.now=()=>now;
    const limited=await check(['README.md'],[run(10,filename),run(11,filename)],context,head,()=>{
      now+=61000;throw Object.assign(new Error('fixed Actions service failure'),{status:500});
    });
    assert.deepEqual(limited,[10]);
  }finally{Date.now=realNow;}
  console.log('PR80_OPTIONAL_CANCEL_HTTP500_BUDGET=PASS');
  console.log('PR80_CI_SELECTOR_PRESERVES_ON_DEMAND_WORKFLOWS_AND_FOREIGN_RUNS=PASS');
})().catch(error => {console.error(error);process.exitCode = 1;});
