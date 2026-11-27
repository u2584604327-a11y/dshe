# P195 — original coroutine Process/reader/latch lifecycle source fixture

**Scope:** exact user-requested DSH v139, sole repository `u2584604327-a11y/dshe`, existing branch, sole Draft PR #80. **NONPRODUCTION**: this code never calls the original `EngineManager` or `ProcessBuilder.start()`, never starts Node, changes an APK, signs anything or uses credentials.

## Why this exists

The fixed-v138 original DEX contract (previous P35 audit) shows the engine's primary coroutine creates the original Java `Process`, stores its handle, starts a reader thread, waits on a `CountDownLatch` and updates `StateFlow`. P37 already implements bounded `Process` stdout/stderr/waitFor/exit semantics, but P184's real Android Binder receipt proof uses only a fixed synthetic child `/system/bin/id -u`. It does **not** prove that P37 is compatible with the complete original coroutine or its actual READY predicate.

## This phase's exact guarantee

`P195OriginalCoroutineLifecycle` is a Java8 **observation-only** state machine. It consumes the exact same-thread/ProcessBuilder/mode/session/owner epoch/sequence seal from P194, binds to an existing exact P37 object, and enforces monotonic observed events: Process field assignment → distinct alive reader Thread → original latch-await *observation* → **reader-reported** `read() == -1` → genuine P37 `REMOTE_EXIT`. Different Process object, stale seal, missing reader, premature latch/exit, false EOF result, lost Binder transport, identity failure or replay revokes the observation. Each prior P194 seal is burned; nothing here mints an Android sender UID or grants a child-start receipt.

The API records an EOF *reported by its caller*, not a cryptographic/Android attestation of the reader. Likewise a caller can claim to have observed the latch and a Java Thread is not a trusted original Kotlin coroutine identity. It is deliberately named `P195OriginalCoroutineLifecycle` for the required **shape**, not for a proven production hook. `hasProductionEngineReady()` always returns false. The fixture never accepts a text marker, token, HTTP string, status, or model response as production READY.

Offline test starts P37 in-memory Java objects in original modes probeBoot=1 (merged stderr), runDumpConfig=2 (split stderr) and start=3 (merged stderr). Actual Java reader threads drain authenticated synthetic P37 frames to EOF. Source fixture checks clean exit including early exit, identity-preserving exact Process reference, marker text not treated as READY, cancellation, stale/mutated P194 seal, lost worker transport, replay, caller-reported non-EOF, and premature state order. The original v138 ProcessBuilder is only modeled by an inert in-memory `ProcessBuilder` object with a deliberately nonexistent command and is **never started**.

`bash host_candidate/p195_coroutine_lifecycle/run_java8.sh` runs only Java8 compilation and in-memory tests; it does not need an emulator or user device.

## Still blocked

A genuine original v138 coroutine/callsite hook must be separately proven at the exact DEX PC and mode, with host-minted epoch, framework `Message.sendingUid`, one-use P184 receipt and authenticated P75 process handoff *without weakening P47*. P37 still denies unaudited stdin. The original Node ARM64/complete FD JS/native workspace, original READY predicate/HTTP token and engine `StateFlow` updates, original ToolRuntime/SessionStore continuation, real signed v139/data-preserving install and P102 user-approved native tool are all **NOT WIRED**. P192 isolated-process localhost TCP was actually denied `BIND_EACCES`; preserve P193 host-owned loopback architecture instead.

Preserve P47 host exec fallback **DENY**, P109 sensitive tools **DENY_ALL**, GS capture **OFF**, no automated CAPTCHA/anti-abuse evasion or account/IP/fingerprint rotation, and the original DSHAPP license/nonendorsement source list in [reference ledger](../../REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md). Formal v139 is **STRUCTURAL_BLOCKED**.
