# P192 — Real Android 35 isolated-UID loopback capability gate

Scope: one pinned original-package P43 ephemeral emulator APK inside the existing
`u2584604327-a11y/dshe` Draft PR #80. Source-only; **never a fixed-signed v139**.

## Why

The user's one P51 ARM64 side-by-side phone test proved original Node ELF can
run a pinned JS probe in an isolated UID. It did NOT prove an isolated process
can bind a loopback server required by the original `EngineManager` HTTP READY.
Android isolated services have no application permissions, and this capability
must be observed in the actual Android35 framework, not inferred from a JVM.

## Admission and provenance

- The workflow checks PR #80, approved repo, exact branch, and three P43 source
  Git blob hashes before altering a disposable checkout.
- Original `P43IsolatedWorker`, `P43ProbeActivity`, and temporary APK builder
  are **not edited in Git**. `prepare_p187_ci.py` injects P187 into these only
  in the ephemeral Actions workspace; then checks the three-path diff.
- P43 original v138 assets/DEX are checked by its existing pinned builder. The
  only new code measures random, one-shot `127.0.0.1` binding and a nonce ACK
  over framework-UID/session-authorized Binder.
- Emulator-only root proves `ro.kernel.qemu=1`; an ephemeral iptables egress
  DENY for the app UID has a specific allow for IPv4 loopback/`lo` only. It is
  not a network permission grant to the isolated UID and never touches phones.
- Strict logcat boundary: exactly four named PASS values **from this run** are
  needed to prove positive capability. `BIND_EACCES`, `CONNECT_EPERM`, missing,
  repeated, or stale results are BLOCKED. The workflow deliberately fails if
  any required metric is not PASS; that is evidence, not an invitation to
  weaken Android security.

## Workflow

`.github/workflows/p192-original-isolated-loopback-android35.yml` triggers on
new P192 files in PR #80, runs scoped Java8 and fake-ADB negative checks, then
builds a **temporary** original-package P43 APK using the existing pinned
builder and Android35 SDK and runs the one-shot P187 cross-UID network probe.
No APK is uploaded; ephemeral signer, test files and emulator are cleaned.
No original EngineManager or production scripts are run.

## Safety and limits

Even if all four indicators PASS, it does not demonstrate actual Node HTTP
listening, real `dsh web: .../?token=...` READY, production FD/Binder broker,
or safe user-data handoff. Keep P47 host fallback denied, P109 native tools
DENY_ALL, GS screenshots OFF, production APK release BLOCKED. Do not repeat the
user's previous P51 phone experiment.
