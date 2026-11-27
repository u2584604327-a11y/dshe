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


def method_references(view,methods,owner,name):
    matching=[method for key,method in methods.items() if key[0]==owner and key[1]==name]
    require(len(matching)==1,'HTTP_VERIFY_METHOD_MISSING')
    return [view.instruction(raw)[1] for raw in view.rows(matching[0]).values()]


def require_call_order(refs,expected,code):
    calls=[ref[:2] for ref in refs if isinstance(ref,tuple) and len(ref)==4 and ref[:2] in expected]
    require(calls==list(expected),code)


def verify_owner_activation(view,methods):
    prefix='Lcom/dsh/android/engine/'
    handoff=prefix+'OriginalMainOwnerHandoff;'
    session=prefix+'OriginalMainTestSession;'
    startup=prefix+'OriginalMainStartup;'
    activity=prefix+'OriginalMainProbeActivity;'
    transport=prefix+'HttpProcessTransport;'
    plan=prefix+'OriginalWebLaunch;'
    launch=prefix+'OriginalAndroidWebLaunch;'
    store=prefix+'DurableSessionSnapshot;'
    verified=prefix+'OriginalMainOwnerHandoff$VerifiedLaunch;'
    child='Lcom/dsh/p37/P37RemoteProcess;'
    builder='Ljava/lang/ProcessBuilder;'
    process='Ljava/lang/Process;'
    string='Ljava/lang/String;'
    def reference(owner,name,returned,*parameters):
        return owner.encode(),name.encode(),tuple(param.encode() for param in parameters),returned.encode()
    def calls(owner,name,*expected):
        selected={ref[:2] for ref in expected}
        refs=method_references(view,methods,owner,name)
        actual=tuple(ref for ref in refs if isinstance(ref,tuple) and len(ref)==4 and ref[:2] in selected)
        require(actual==expected,'MAIN_TEST_OWNER_ACTIVATION_CALL_ORDER')
    calls(activity,'verify',reference(handoff,'offer',handoff,launch,session,child,store),
          reference(activity,'invokeOriginalCoroutine','V',launch),reference(handoff,'verifiedLaunch',verified),
          reference(activity,'verifyOriginalReadyState','V',launch,verified),
          reference(handoff,'acceptOriginalReady','V',verified),
          reference(activity,'stopOriginalEngine','V',launch))
    calls(activity,'expectUnarmedCoroutineDenied',reference(activity,'invokeOriginalCoroutine','V',launch))
    calls(activity,'verifyOriginalReadyState',reference(activity,'originalProcess','Ljava/lang/Object;',launch),
          reference(activity,'originalState','Ljava/lang/Object;',launch),
          reference(startup,'requireVerifiedReady','V',process,string))
    calls(activity,'stopOriginalEngine',reference(activity,'originalState','Ljava/lang/Object;',launch),
          reference(activity,'originalProcess','Ljava/lang/Object;',launch))
    calls(handoff,'prepareOriginal',reference(handoff,'requireFresh','V'),
          reference(session,'ownsReservation','Z',launch,child),reference(plan,'requireSame','V',builder))
    calls(handoff,'claimOrDeny',reference('Lcom/dsh/android/p47/P47LaunchGate;','startOrDeny',process,builder),
          reference(handoff,'activate',process,builder))
    calls(handoff,'activate',reference(plan,'requireSame','V',builder),reference(handoff,'requireFresh','V'),
          reference(session,'openLaunchTransport',transport,child,launch,store),
          reference(startup,'await',startup,transport),reference(startup,'verifyForReady',string),
          reference(startup,'requireVerifiedReady','V',process,string),
          reference(session,'ownsLaunch','Z',launch,transport),reference(transport,'hasCurrentReadyProof','Z'))
    calls(session,'openLaunchTransport',reference(session,'ownsReservation','Z',launch,child),
          reference(session,'transferResources','V',child),reference(session,'ownsChild','Z',child),
          reference(transport,'forOriginalWebLaunch',transport,process,string,'J',plan,store))
    calls(session,'transferResources',reference('Lcom/dsh/android/p50/P50ModuleStream;','writeOriginalForService',
          'Lcom/dsh/android/p77/P77TarAudit$Result;','Ljava/io/InputStream;','Ljava/io/OutputStream;'))
    require(not any(ref[0] in (session.encode(),startup.encode()) and
                    ref[1] in (b'openLaunchTransport',b'await',b'verifyForReady')
                    or ref[:2]==(activity.encode(),b'invokeOwnedStart')
                    for ref in method_references(view,methods,activity,'verify')
                    if isinstance(ref,tuple) and len(ref)==4),'MAIN_TEST_ACTIVITY_STARTS_BEFORE_BRIDGE')


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
        if args.owner_bound:
            verify_owner_activation(view,methods)
        elif main:
            refs=method_references(view,methods,'Lcom/dsh/android/engine/OriginalMainProbeActivity;','verify')
            expected=([b'await',b'verifyForReady',b'requireVerifiedReady'] if args.owned_ready else
                      [b'await',b'authenticate',b'verifyFrontend'])
            require_call_order(refs,[(b'Lcom/dsh/android/engine/OriginalMainStartup;',name) for name in expected],
                               'MAIN_TEST_PRIVATE_STARTUP_CALLS')
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
    if args.owner_bound:print('MAIN_TEST_OWNER_BRIDGE_ACTIVATES_VERIFIED_RESOURCES_AND_HTTP=PASS_STATIC')
    print('HTTP_TEST_ARM64_NODE_HTTP_RUNTIME=REQUIRES_DEVICE')


if __name__=='__main__':main()
