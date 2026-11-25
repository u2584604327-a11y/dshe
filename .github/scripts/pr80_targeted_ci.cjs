// PR path filters include the whole PR diff. Retire unrelated repetitions;
// cancellation is NOT a passing test result. Never cancel another PR or SHA.
const fs = require('node:fs');

const ALWAYS = new Set([
  'p139-p51-arm64-sidecar-test-apk-artifact.yml',
  'p37-remote-process-contract.yml',
  'p141-original-engine-stderr-merge.yml', 'p195-coroutine-process-lifecycle.yml',
  'p184-android35-real-p68-p75-receipt.yml', 'p184-verified-child-start-receipt.yml',
]);

const DEX_GATES = new Set(['p245-build-only-probe.yml',
  'p310-original-art-verify-one-shot.yml', 'p311-original-target-class-link.yml']);
const DEX_INPUTS = ['host_candidate/p40_', 'host_candidate/p43_original_service/',
  'host_candidate/p47_no_fallback/', 'host_candidate/p209_', 'host_candidate/p245_',
  'host_candidate/p279_', 'host_candidate/p285_', 'host_candidate/p289_',
  'host_candidate/p291_', 'host_candidate/p294_', 'host_candidate/p310_', 'host_candidate/p311_'];

function relevant(text, changed) {
  // Retain workflows without a simple positive path list, and those using
  // exclusion patterns or syntax this conservative selector cannot interpret.
  const block = text.match(/\n    paths:\s*\n((?:      - [^\n]+\n)+)/);
  if (!block) return true;
  const patterns = [];
  for (const line of block[1].trimEnd().split('\n')) {
    const match = line.match(/^      - (['"])([^'"]+)\1\s*$/);
    if (!match || match[2].startsWith('!') || /[\[\]{}]/.test(match[2])) return true;
    patterns.push(match[2]);
  }
  for (const filename of changed) {
    // Compile/provenance inputs can extend beyond a workflow's trigger list.
    const area = filename.startsWith('host_candidate/') ? filename.split('/').slice(0, 2).join('/') + '/' : filename;
    if (text.includes(area)) return true;
    for (const pattern of patterns) {
      // '*' deliberately includes '/' here: over-selection preserves tests.
      const expression = pattern.replace(/[.+^$()|\\]/g, '\\$&').replace(/\*+/g, '.*').replace(/\?/g, '.');
      if (new RegExp('^' + expression + '$').test(filename)) return true;
      // A globstar directory may be absent. Keep ambiguous zero-directory matches.
      if (pattern.includes('**/')) {
        const short = pattern.replace(/\*\*\//g, '').replace(/[.+^$()|\\]/g, '\\$&').replace(/\*+/g, '.*').replace(/\?/g, '.');
        if (new RegExp('^' + short + '$').test(filename)) return true;
      }
    }
  }
  return false;
}

module.exports = async function select({github, context, core}) {
  const repo = {owner: context.repo.owner, repo: context.repo.repo};
  const event = context.payload;
  const pr = event.pull_request;
  const branch = 'dsh/p96-original-engine-stream-owner-narrow-20261030';
  if (repo.owner !== 'u2584604327-a11y' || repo.repo !== 'dshe' || event.action !== 'synchronize' ||
      pr?.number !== 80 || pr.head?.repo?.full_name !== 'u2584604327-a11y/dshe' ||
      pr.head?.ref !== branch || !/^[0-9a-f]{40}$/.test(event.before ?? '') ||
      event.after !== pr.head.sha) return;
  const current = await github.rest.pulls.get({...repo, pull_number: 80});
  if (current.data.head.sha !== pr.head.sha) return;
  const compared = await github.rest.repos.compareCommitsWithBasehead({...repo,
    basehead: event.before + '...' + pr.head.sha});
  const comparison = compared.data;
  if (comparison.status !== 'ahead' || !comparison.files?.length || comparison.files.length >= 300) return;
  const changed = comparison.files.flatMap(file => [file.filename, file.previous_filename].filter(Boolean));
  const runs = await github.paginate(github.rest.actions.listWorkflowRunsForRepo,
    {...repo, event: 'pull_request', head_sha: pr.head.sha, per_page: 100});
  let cancelled = 0;
  for (const run of runs) {
    if (!Array.isArray(run.pull_requests) || run.pull_requests.length !== 1 ||
        run.pull_requests[0].number !== 80 ||
        run.id === context.runId || run.head_sha !== pr.head.sha || run.head_branch !== branch ||
        run.event !== 'pull_request' || !['queued', 'in_progress', 'pending', 'waiting', 'requested'].includes(run.status) ||
        !/^\.github\/workflows\/[a-zA-Z0-9_.-]+\.ya?ml$/.test(run.path)) continue;
    const name = run.path.split('/').at(-1);
    if (ALWAYS.has(name)) continue;
    if (DEX_GATES.has(name) && changed.some(file => DEX_INPUTS.some(prefix => file.startsWith(prefix)))) continue;
    let source;
    try {source = fs.readFileSync(run.path, 'utf8');} catch {continue;}
    if (relevant(source, changed)) continue;
    try {
      await github.rest.actions.cancelWorkflowRun({...repo, run_id: run.id});
      core.info('NOT_TESTED_CANCELLED_UNRELATED_CHANGE run=' + run.id + ' workflow=' + name);
      cancelled++;
    } catch (error) {
      // A run may finish between listing and cancellation; never mask failures.
      core.warning('Could not cancel unrelated run ' + run.id + ': HTTP ' + (error.status ?? 'unknown'));
    }
  }
  await core.summary.addRaw('PR #80 targeted CI: cancelled ' + cancelled +
    ' unrelated repetitions. Cancelled checks are NOT_TESTED, never PASS.\n').write();
  // New runtime transport is not compiled into the P51 config APK. Reuse the
  // already device-accepted artifact unless an APK/CI input also changed.
  // Unknown changes retain the build; cancellation/skip never means PASS.
  const onlyTransport = changed.length > 0 && changed.every(file =>
    file.startsWith('host_candidate/engine_runtime/') ||
    file === '.github/workflows/engine-runtime-http.yml' ||
    file === '.github/workflows/p37-remote-process-contract.yml');
  return {artifactNeeded: !onlyTransport};
};
