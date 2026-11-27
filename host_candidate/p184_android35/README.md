# P184 Android 35 — original-v138-derived genuine Binder receipt (test only)

Status: candidate code. It is NOT a completed Android acceptance until its exact-HEAD GitHub Actions job has actually run and its log markers pass.

## Chain under test

P43 same-package original-v138-derived temporary test APK binds an isolatedProcess service using the existing SHA-pinned P44/P45/P46 host session and read-only asset FD. Real P48 fixed isolated child runs precisely /system/bin/id -u. Its HELLO frame is never treated as an engine start. After the isolated child actually starts, its CHILD_STARTED Messenger frame supplies Android framework Message.sendingUid to the trusted P68/P67 intake. Opted-in P68 mints a short-lived, package-private P184ChildStartReceipt bound to the exact P37 remote Process, host-minted 64-hex session, real isolated UID and trusted test owner epoch.

The separately opted-in P75 pending generation rejects the old caller-provided UID/verifier callback, then consumes the actual one-shot P68 receipt. The main Android probe also submits the same receipt a second time and proves rejection. An unrelated host-side test thread calls P75.startOrDeny with only hardcoded /system/bin/id -u and checks identical P37 Process object handoff. It does NOT invoke original P40ProcessBridge or the real EngineManager coroutine. Both original production process spawn paths, original v138 assets, second DEX, signing and private user data are unmodified.

## Strict test boundary

- Exactly one repository, branch and Draft PR. SHA-pinned CI patcher changes only P43ProbeActivity.java and build_embedded_emulator_apk.sh in disposable workflow checkout; no DEX or user APK source edits committed.
- Never run on owner phone. The emulator runner asserts QEMU/root and a fresh absent com.dsh.android, uses a new disposable signing identity, blocks ALL app-host IPv4 and IPv6 egress, and uninstalls only the temporary test package it installed.
- Read only current-run logcat markers, never print private Binder sessions, nonce, actual UID or host files. Require original P43 isolated UID handshake, P75 original-engine THREAD-STAND-IN waiting, P184 legacy callback DENY, exact one-use receipt PASS, replay DENY, real P68 UID receipt, identical P37 handoff and eventual correct fixed child EOF/exit.
- Real Android35 x86_64 emulator acceptance proves only the listed fixed synthetic child receipt. It does NOT prove the production original ARM64 Node, complete JS bundle via FD, HTTP token READY, live EngineManager owner generation, original SessionStore/ToolRuntime callback, user account/browser isolation, a full Android VM, a data-preserving v139 update, or security-policy avoidance.

Existing P192 isolated TCP BIND_EACCES is frozen negative evidence; do not grant an isolated process network permission or weaken SELinux/P47 host fallback/P109 native tool DENY_ALL. GS screenshot capture remains OFF. References, MIT attribution and unofficial modification disclaimers: REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md, README.md and NOTICE.md at repository root. Formal v139 remains STRUCTURAL_BLOCKED.
