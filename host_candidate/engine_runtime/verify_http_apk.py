#!/usr/bin/env python3
"""Actual network-test APK, strict resources/manifest and negative mutations."""
import argparse
import copy
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from loguru import logger
logger.remove()
import p49_original_node_stage as stage
from http_manifest import verify_apk
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'p245_build_only_probe'))
from strict_dex import DexView,index


def require(value,code):
    if not value:raise RuntimeError(code)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original',type=Path);parser.add_argument('candidate',type=Path)
    parser.add_argument('--original-main-profile',action='store_true')
    parser.add_argument('--owned-ready',action='store_true')
    parser.add_argument('--owner-bound',action='store_true')
    args=parser.parse_args()
    main=args.original_main_profile
    require(not args.owner_bound or main,'OWNER_BOUND_MAIN_ONLY')
    if main:
        from main_manifest import verify_apk as manifest_check
    else:manifest_check=verify_apk
    manifest_check(args.candidate);stage.verify(args.original,args.candidate,False,not main,main)
    with zipfile.ZipFile(args.candidate) as archive:
        view=DexView(archive.read('classes3.dex'));methods=index(view.dex)
        needed=['Lcom/dsh/android/engine/HttpProcessTransport;',
                'Lcom/dsh/android/engine/OriginalHttpProbeActivity;',
                'Lcom/dsh/android/engine/OriginalHttpIsolatedService;',
                'Lcom/dsh/android/engine/DurableSessionSnapshot;',
                'Lcom/dsh/android/engine/SessionSnapshotCodec;']
        if main:needed+=['Lcom/dsh/android/engine/OriginalMainProbeActivity;',
                         'Lcom/dsh/android/engine/OriginalMainTestSession;',
                         'Lcom/dsh/android/engine/OriginalMainIsolatedService;',
                         'Lcom/dsh/android/engine/OriginalMainHttpChecks;',
                         'Lcom/dsh/android/engine/OriginalMainStartup;']
        if args.owner_bound:needed+=['Lcom/dsh/android/engine/OriginalWebLaunch;',
                                     'Lcom/dsh/android/engine/OriginalAndroidWebLaunch;',
                                     'Lcom/dsh/android/engine/OriginalMainOwnerHandoff;']
        require(all(any(key[0]==name for key in methods) for name in needed),'HTTP_CLASSES_MISSING')
        if main:
            body=[method for key,method in methods.items()
                  if key[0]=='Lcom/dsh/android/engine/OriginalMainProbeActivity;' and key[1]=='verify']
            require(len(body)==1,'MAIN_TEST_VERIFICATION_METHOD')
            refs=[view.instruction(raw)[1] for raw in view.rows(body[0]).values()]
            expected=([b'await',b'verifyForReady',b'requireVerifiedReady'] if args.owned_ready or args.owner_bound else
                      [b'await',b'authenticate',b'verifyFrontend'])
            calls=[ref[1] for ref in refs if isinstance(ref,tuple) and len(ref)==4 and
                   ref[0]==b'Lcom/dsh/android/engine/OriginalMainStartup;' and
                   ref[1] in expected]
            require(calls==expected,'MAIN_TEST_PRIVATE_STARTUP_CALLS')
        if args.owner_bound:
            handoff=[method for key,method in methods.items() if key[0]==needed[-1] and key[1]=='claimOrDeny']
            require(len(handoff)==1,'MAIN_TEST_OWNER_BOUND_WRAPPER')
            refs=[view.instruction(raw)[1] for raw in view.rows(handoff[0]).values()]
            require(refs.count((b'Lcom/dsh/android/p47/P47LaunchGate;',b'startOrDeny',
                                (b'Ljava/lang/ProcessBuilder;',),b'Ljava/lang/Process;'))==1,
                    'MAIN_TEST_OWNER_BOUND_FAIL_CLOSED')
        for key,method in methods.items():
            if key[0] in ([needed[1]]+needed[5:]) and method.get_code():
                require(not any(view.instruction(raw)[1]==(b'Ljava/lang/ProcessBuilder;',b'start',(),b'Ljava/lang/Process;')
                    for raw in view.rows(method).values()),'HTTP_HOST_EXEC_FALLBACK')
        service='OriginalMainIsolatedService' if main else 'OriginalHttpIsolatedService'
        inbox=[method for key,method in methods.items() if key[0].startswith('Lcom/dsh/android/engine/'+service+'$') and key[1]=='handleMessage']
        require(len(inbox)==1,'HTTP_WORKER_INBOX')
        refs=[view.instruction(raw)[1] for raw in view.rows(inbox[0]).values()]
        require((b'Landroid/os/Message;',b'sendingUid',b'I') in refs,'FRAMEWORK_BINDER_UID_NOT_READ')
        require((b'Lcom/dsh/android/p50/P50OriginalNodeFixedChild;',b'originalWebMainTest' if main else b'originalHttpServices',
                 (b'Landroid/content/Context;',b'Landroid/os/Messenger;',b'Ljava/lang/String;',b'Lcom/dsh/android/p68/P68AndroidBinderIntake$WorkerPipes;'),
                 b'Lcom/dsh/android/p50/P50OriginalNodeFixedChild;') in refs,'HTTP_FIXED_VERIFIED_CHILD_FACTORY')
    with tempfile.TemporaryDirectory(prefix='http-apk-negative-') as folder:
        negative=Path(folder)/'negative.apk'
        def denied(path,explicit,expected):
            try:stage.verify(args.original,path,False,explicit and not main,explicit and main)
            except RuntimeError as error:require(str(error)=='P49_BLOCKED_'+expected,'WRONG_HTTP_ASSET_REJECTION')
            else:raise RuntimeError('HTTP_ASSET_NEGATIVE_ACCEPTED')
        denied(args.candidate,False,'ADDITIONAL_ARM64_LIB_SET_CHANGED')
        shutil.copyfile(args.candidate,negative)
        with zipfile.ZipFile(negative,'a') as archive:archive.writestr('assets/unapproved-http.js',b'bad')
        denied(negative,True,'UNAUTHORIZED_EXTRA_ASSET_OR_LIB')
        with zipfile.ZipFile(args.candidate) as source,zipfile.ZipFile(negative,'w') as output:
            for item in source.infolist():
                payload=source.read(item)
                if item.filename==('assets/engine-original-main.mjs' if main else 'assets/engine-http-services.mjs'):payload=bytes([payload[0]^1])+payload[1:]
                cloned=copy.copy(item);cloned.compress_type=zipfile.ZIP_STORED;output.writestr(cloned,payload)
        denied(negative,True,'MAIN_BOOTSTRAP_SHA_OR_LENGTH' if main else 'HTTP_BOOTSTRAP_SHA_OR_LENGTH')
    print('HTTP_TEST_ACTUAL_APK_BINDER_UID_FIXED_CHILD_AND_NO_HOST_EXEC=PASS_STATIC')
    print('HTTP_TEST_EXPLICIT_BOOTSTRAP_AND_DEFAULT_ALLOWLIST_NEGATIVES=PASS')
    if main:print('MAIN_TEST_PRIVATE_STARTUP_AUTH_AND_FRONTEND_CALLS_IN_ACTUAL_APK=PASS_STATIC')
    print('HTTP_TEST_ARM64_NODE_HTTP_RUNTIME=REQUIRES_DEVICE')


if __name__=='__main__':main()
