#!/usr/bin/env python3
"""CI-only separate host-network full original main TEST APK. No production
identity, original app data, broad permissions or production P47 registration.
"""
from pathlib import Path
import json
import os
import subprocess

ROOT=Path(__file__).resolve().parents[2]
BUILDER='host_candidate/p43_original_service/build_embedded_emulator_apk.sh'
GATE='host_candidate/p47_no_fallback/p47_gate.py'
PINS={BUILDER:'62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f',GATE:'49f0d5d07cf7e8fa1e0323c945ddbb1eed946065'}
REPO='u2584604327-a11y/dshe'
BRANCH='dsh/p96-original-engine-stream-owner-narrow-20261030'


def once(source,old,new):
    if source.count(old)!=1:raise RuntimeError('HTTP_TEST_PATCH_ANCHOR')
    return source.replace(old,new)


def patches(sources):
    guard=once(sources[GATE],'os.environ.get("P51_SIDE_BY_SIDE","0")=="0",',
        '(os.environ.get("P51_SIDE_BY_SIDE","0")=="0" or\n'
        '          (os.environ.get("P51_SIDE_BY_SIDE")=="1" and\n'
        '           os.environ.get("HTTP_COMPONENT_TEST")=="1" and\n'
        '           os.environ.get("GITHUB_ACTIONS")=="true")),')
    # The separate APK uses the receiver-bearing call. The strict DEX verifier
    # independently checks its exact PC, register words and wrapper body.
    owner_call=('Lcom/dsh/android/engine/OriginalStartupDiagnostics;->startOwned('
                'Ljava/lang/ProcessBuilder;Lcom/dsh/android/EngineManager;)')
    guard=once(guard,'    need(m[target]["calls"].count(("invoke-static",TRAMPOLINE))==1,',
        f'    need(sum((op,"".join(call.split())) == ("invoke-static",{owner_call!r})\n'
        '             for op,call in m[target]["calls"])==1 and\n'
        '         ("invoke-static",TRAMPOLINE) not in m[target]["calls"],')
    builder=once(sources[BUILDER],
        'test "${P47_NO_HOST_FALLBACK:-0}" = 1 && test "${P51_SIDE_BY_SIDE:-0}" = 0 || {',
        'test "${P47_NO_HOST_FALLBACK:-0}" = 1 && { test "${P51_SIDE_BY_SIDE:-0}" = 0 ||\n'
        '    { test "${P51_SIDE_BY_SIDE:-0}" = 1 && test "${HTTP_COMPONENT_TEST:-0}" = 1 && test "${GITHUB_ACTIONS:-false}" = true; }; } || {')
    # The original permissionless P51 manifest/gate is never modified.
    if builder.count('host_candidate/p51_side_by_side/p51_manifest.py')!=3:raise RuntimeError('HTTP_TEST_MANIFEST_CALL_COUNT')
    builder=builder.replace('host_candidate/p51_side_by_side/p51_manifest.py','host_candidate/engine_runtime/main_manifest.py')
    builder=once(builder,'apktool b "$DIR/decoded" -o "$DIR/rebuilt-unsigned.apk"',
        'python host_candidate/engine_runtime/original_startup_diagnostics.py "$ORIGINAL" "$DIR/decoded" --owner-bound\n'
        'python host_candidate/engine_runtime/prepare_main_runtime.py prepare "$ORIGINAL" "$DIR/decoded"\n'
        'apktool b "$DIR/decoded" -o "$DIR/rebuilt-unsigned.apk"')
    builder=once(builder,
        '  python host_candidate/p49_original_node_stage.py embed "$DIR/with-p43-dex.apk" "$DIR/p49"',
        '  python host_candidate/p49_original_node_stage.py embed "$DIR/with-p43-dex.apk" "$DIR/p49"\n'
        '  python host_candidate/engine_runtime/prepare_main_runtime.py embed "$ORIGINAL" "$DIR/with-p43-dex.apk"')
    anchor='  host_candidate/p50_original_arm64_node/android/com/dsh/android/p50/P50OriginalNodeFixedChild.java \\\n'
    builder=once(builder,anchor,anchor+''.join('  '+name+' \\\n' for name in [
        'host_candidate/p50_original_arm64_node/android/com/dsh/android/p50/P50ModuleStream.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/HttpProcessTransport.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/DurableSessionSnapshot.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/SessionSnapshotCodec.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/OriginalMainHttpChecks.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/OriginalMainStartup.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/OriginalWebLaunch.java',
        'host_candidate/engine_runtime/src/com/dsh/android/engine/OriginalClientPlugin.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalRuntimeSource.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalAndroidWebLaunch.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalMainOwnerHandoff.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalMainTestSession.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalMainIsolatedService.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalMainProbeActivity.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalHttpIsolatedService.java',
        'host_candidate/engine_runtime/android/com/dsh/android/engine/OriginalHttpProbeActivity.java']))
    builder=once(builder,'    "$ORIGINAL" "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk"\nfi\nif test "${P47_NO_HOST_FALLBACK:-0}" = 1;',
        '    "$ORIGINAL" "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk" --original-main-profile\nfi\nif test "${P47_NO_HOST_FALLBACK:-0}" = 1;')
    builder=once(builder,'''  test ! -s "$DIR/candidate-perms.txt" || {
    echo 'P51_BLOCKED_SIDE_BY_SIDE_HAS_PERMISSIONS';exit 1;
  }''','''  test "$(cat "$DIR/candidate-perms.txt")" = "uses-permission: name='android.permission.INTERNET'" || {
    echo HTTP_TEST_PERMISSION_DRIFT;exit 1;
  }''')
    builder=once(builder,"echo 'P51_NO_PERMISSIONS_AND_SEPARATE_SIGNER=PASS'","echo 'HTTP_TEST_INTERNET_ONLY_AND_SEPARATE_SIGNER=PASS'")
    return {BUILDER:builder,GATE:guard}


def main():
    required={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':REPO,'GITHUB_EVENT_NAME':'pull_request',
              'P47_NO_HOST_FALLBACK':'1','P49_NODE_STAGE':'1','P51_SIDE_BY_SIDE':'1',
              'P181_THREE_ORIGINAL_START_DENY':'1','HTTP_COMPONENT_TEST':'1'}
    if any(os.environ.get(key)!=value for key,value in required.items()):raise RuntimeError('HTTP_TEST_TRUSTED_DISPOSABLE_CI_ONLY')
    event=json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text());pr=event.get('pull_request',{});head=pr.get('head',{})
    if pr.get('number')!=80 or head.get('ref')!=BRANCH or head.get('repo',{}).get('full_name')!=REPO:raise RuntimeError('HTTP_TEST_PR_SCOPE')
    def git(*args):return subprocess.check_output(['git',*args],text=True).strip()
    if git('status','--porcelain') or git('rev-parse','HEAD')!=head.get('sha'):raise RuntimeError('HTTP_TEST_UNPINNED_OR_DIRTY_SOURCE')
    if not git('remote','get-url','origin').removesuffix('.git').endswith('/'+REPO):raise RuntimeError('HTTP_TEST_WRONG_REPOSITORY')
    for name,pin in PINS.items():
        if git('hash-object',name)!=pin:raise RuntimeError('HTTP_TEST_PIN_CHANGED')
    digest="c25e4f8be63a7bc1a6b8d5ee114a6e81c5362febba3ab4c9387909b92cdafde3"
    java=Path('host_candidate/p50_original_arm64_node/android/com/dsh/android/p50/P50OriginalNodeFixedChild.java').read_text()
    if 'MAIN_TEST_BOOTSTRAP_SHA="'+digest+'"' not in java:raise RuntimeError('HTTP_TEST_COMPOSED_BOOTSTRAP_PIN')
    for name,text in patches({name:Path(name).read_text() for name in PINS}).items():Path(name).write_text(text)
    if set(git('diff','--name-only').splitlines())!=set(PINS):raise RuntimeError('HTTP_TEST_PATCH_SCOPE')
    print('HTTP_TEST_SEPARATE_NETWORK_COMPONENT_BUILD=PREPARED_NOT_PRODUCTION')


if __name__=='__main__':main()
