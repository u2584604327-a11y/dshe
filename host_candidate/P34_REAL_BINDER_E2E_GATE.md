# P34 real Android35 Binder/UI host broker e2e and P33 original DEX entrypoint facts

## Actual signed v138 P33 source evidence
From exact v138 SHA-pinned DEX scan, GitHub Actions success
https://github.com/u2584604327-a11y/dshe/actions/runs/40880285767

- Application method implementations: 4592; direct app calls: 6149.
- 8 direct ProcessBuilder.start invocations and 11 WebView
  addJavascriptInterface/evaluateJavascript/loadUrl invocations.
- Most relevant original Node startup candidate:
  EngineManager$start$2.invokeSuspend, classes.dex code_off=3163260,
  invoke PC=3912 (original DEX PC units reported by androguard).
- Other EngineManager process callsites: probeBoot
  code_off=3176996, pc=310 and runDumpConfig
  code_off=3176192, pc=472.
- TermuxBootstrap.nodeIsUsable code_off=3535080, pc=232.
- Separate unsafe generic direct ProcessBuilder callsites include
  RootAccess.probe, WirelessDebugging.runRunner and
  termux/tool/AppShellExecutor.run; DO NOT reroute these indiscriminately.
- Browser: AiBrowserView.evaluate at code_off=3429268, pc=52;
  SystemWebHost constructor addJavascriptInterface at code_off=3559316,
  pc=400; these are not Node spawn callsites.
- Existing original DSH host code remains an APK, not a full Android
  source tree. These static locations alone are not safe mutation sites.
  No original DEX/APK has been rewritten, signed or installed.

## P34 new real-Android integration evidence
P32 host Binder adapter compiled and Java one-shot grant policy PASSED
in https://github.com/u2584604327-a11y/dshe/actions/runs/40877119423
but has not been tested as a real Android Service/Activity together.

P34 builds an independently named **DISPOSABLE** zero-permission
Android 35 x86_64 lab APK, with real:
- P32AndroidBinderPort and P32NodeIpcBroker/P17CapabilityGate source
  compiled into a trusted Android Activity.
- Android isolatedProcess=true nonexported Worker running as an OS
  isolated UID and speaking real Messenger Binder IPC.
- Explicit trusted host begin-binding HELLO, framework-supplied sender
  UID and host-minted per-binding session, no implicit grant.
- Synthetic fixed canonical frame METADATA_COUNT limit 3. This frame
  is generated in the isolated worker for testing **only**. It does NOT
  originate from the signed original ARM64 Node executable.
- Before any UI touch, worker must receive DENY_NO_GRANT.
- Exactly one real emulator touch to trusted native Button grants a
  10-second capability to the bound session. Worker must get one
  ALLOW_COUNT=3 and then DENY_NO_GRANT on replay.
- Android UI transitions to HOME must call trusted background grant
  revocation lifecycle path.
- No INTERNET, storage, camera, microphone, location, shell, root,
  diagnostics, user files or original signer. Test APK destroyed after CI,
  never uploaded as an artifact or private release.

## Explicit blockers after P34
1. No original ARM64 Node process in x86_64 Android35 CI test.
2. No original EngineManager$start$2 -> isolated Worker migration.
3. No real Node stdout -> Binder host capability under actual original
   DSH. A synthetic worker frame is NOT proof of actual model tool flow.
4. Full MainActivity/browser/engine/chat/logs/streaming/attachments/
   plugin/diagnostic control regression still missing.
5. Original signing key not used/uploaded; versionCode 139 not built,
   no installed phone changes or production deployment.

P33_ORIGINAL_PROCESS_START_CALLSITES=PASS_STATIC_8
P33_ORIGINAL_ENGINEMANAGER_START_EDGE=LOCATED_NOT_PATCHED
P34_ANDROID35_ISOLATED_WORKER_BINDER_UI_E2E=CI_PENDING
P34_REAL_ORIGINAL_NODE_TO_HOST_BRIDGE=NOT_IMPLEMENTED
P34_PRODUCTION_SIGNED_DSH_V139=BLOCKED
