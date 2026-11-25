#!/usr/bin/env python3
"""Wire the real original default-config route only into a disposable P51 APK."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO = 'u2584604327-a11y/dshe'
BRANCH = 'dsh/p96-original-engine-stream-owner-narrow-20261030'
BASE = 'host_candidate/p43_original_service/'
ACTIVITY = BASE + 'android/com/dsh/android/p43/P43ProbeActivity.java'
WORKER = BASE + 'android/com/dsh/android/p43/P43IsolatedWorker.java'
BUILDER = BASE + 'build_embedded_emulator_apk.sh'
MODULE = 'host_candidate/p50_original_arm64_node/'
PINS = {ACTIVITY: '8a83ef4c53c8e527f604023ab5eec2be8f2e12a9',
        WORKER: '62a616d07e65e71cb671a8171b4c02ce3faf96a7',
        BUILDER: '62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f'}


def once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError('ORIGINAL_MODULE_SOURCE_ANCHOR_CHANGED')
    return source.replace(old, new)


def patches(sources):
    activity = once(sources[ACTIVITY], '  private P48HostProcessProbe p48;',
                    '  private P48HostProcessProbe p48;\n'
                    '  private com.dsh.android.p50.P50OriginalModuleProbe originalModules;')
    activity = once(activity, '      if(remote!=null && p48==null) {', '''      if(remote!=null && originalModules==null &&
          "com.dsh.p51.isolatedprobe".equals(getPackageName())) {
        originalModules=new com.dsh.android.p50.P50OriginalModuleProbe(
            P43ProbeActivity.this,remote,session,line->log(line));
        originalModules.start();
        return; // Default config only: no original UI, P47 or HTTP authorization.
      }
      if(remote!=null && p48==null) {''')
    for callback, code in [('onServiceDisconnected', 'SERVICE_DISCONNECTED'),
                           ('onBindingDied', 'BINDING_DIED'), ('onNullBinding', 'NULL_BINDING')]:
        activity = once(activity, '    @Override public void ' + callback +
                        '(ComponentName n){fail("' + code + '");}',
                        '    @Override public void ' + callback + '(ComponentName n){'
                        'if(originalModules!=null)originalModules.close();fail("' + code + '");}')
    activity = once(activity, '  @Override protected void onDestroy(){',
                    '  @Override protected void onDestroy(){\n'
                    '    if(originalModules!=null)originalModules.close();')
    worker = once(sources[WORKER], '        if("p50-exact-original-node".equals(mode)) {', '''        if("p50-original-default-config".equals(mode)) {
          if(!"com.dsh.p51.isolatedprobe".equals(getPackageName()))return;
          WorkerPipes pipes=null;
          try {
            pipes=WorkerPipes.receive(message.getData().getBundle("process_pipes"),
                message.sendingUid,acceptedHostUid);
            p50Child=P50OriginalNodeFixedChild.originalDefaultConfig(
                P43IsolatedWorker.this,message.replyTo,acceptedSession,pipes);
            p50Child.start();
          }catch(IOException|RuntimeException denied){if(pipes!=null)pipes.close();}
        } else if("p50-exact-original-node".equals(mode)) {''')
    builder = once(sources[BUILDER], 'apktool b "$DIR/decoded" -o "$DIR/rebuilt-unsigned.apk"',
                   'cp ' + MODULE + 'original_modules.mjs "$DIR/decoded/assets/p50-original-modules.mjs"\n'
                   'apktool b "$DIR/decoded" -o "$DIR/rebuilt-unsigned.apk"')
    anchor = '  ' + MODULE + 'android/com/dsh/android/p50/P50OriginalNodeFixedChild.java \\\n'
    builder = once(builder, anchor, anchor + ''.join(
        '  ' + MODULE + 'android/com/dsh/android/p50/' + name + '.java \\\n'
        for name in ('P50OriginalModuleProbe', 'P50ModuleStream')))
    builder = once(builder, '    "$ORIGINAL" "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk"\nfi\nif test "${P47_NO_HOST_FALLBACK:-0}" = 1;',
                   '    "$ORIGINAL" "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk" --original-default-config\nfi\nif test "${P47_NO_HOST_FALLBACK:-0}" = 1;')
    return {ACTIVITY: activity, WORKER: worker, BUILDER: builder}


def main():
    required = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': REPO,
                'GITHUB_EVENT_NAME': 'pull_request', 'P51_SIDE_BY_SIDE': '1',
                'P47_NO_HOST_FALLBACK': '1', 'P49_NODE_STAGE': '1'}
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise RuntimeError('ORIGINAL_MODULE_DISPOSABLE_CI_ONLY')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    pr = event.get('pull_request', {})
    head = pr.get('head', {})
    if (pr.get('number') != 80 or head.get('ref') != BRANCH or
            head.get('repo', {}).get('full_name') != REPO):
        raise RuntimeError('ORIGINAL_MODULE_WRONG_PR')
    def git(*args):
        return subprocess.check_output(['git', *args], text=True).strip()
    if git('status', '--porcelain') or git('rev-parse', 'HEAD') != head.get('sha'):
        raise RuntimeError('ORIGINAL_MODULE_DIRTY_OR_UNPINNED_HEAD')
    if not git('remote', 'get-url', 'origin').removesuffix('.git').endswith('/' + REPO):
        raise RuntimeError('ORIGINAL_MODULE_WRONG_REPOSITORY')
    for name, expected in PINS.items():
        if git('hash-object', name) != expected:
            raise RuntimeError('ORIGINAL_MODULE_PIN_CHANGED_' + name)
    digest = hashlib.sha256(Path(MODULE + 'original_modules.mjs').read_bytes()).hexdigest()
    if ('MODULE_BOOTSTRAP_SHA="' + digest + '"') not in Path(
            MODULE + 'android/com/dsh/android/p50/P50OriginalNodeFixedChild.java').read_text():
        raise RuntimeError('ORIGINAL_MODULE_BOOTSTRAP_PIN_CHANGED')
    for name, content in patches({name: Path(name).read_text() for name in PINS}).items():
        Path(name).write_text(content)
    if set(git('diff', '--name-only').splitlines()) != set(PINS):
        raise RuntimeError('ORIGINAL_MODULE_PATCH_SCOPE_CHANGED')
    print('ORIGINAL_MODULE_P51_DISPOSABLE_CONFIG_ROUTE=PASS_NOT_PRODUCTION')


if __name__ == '__main__':
    main()
