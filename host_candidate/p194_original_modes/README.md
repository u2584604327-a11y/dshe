# P194 — original v138 EngineManager three-mode owner-shape preflight

STATUS: SOURCE-ONLY, zero production runtime authorization. This candidate is additive to the sole Draft PR #80 in u2584604327-a11y/dshe, existing branch. No production APK/DEX/user phone, Node execution, network, account or signing changes.

## Exact original evidence, not extrapolation

P35 pins the signed original v138 APK SHA256 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5, with the primary original EngineManager coroutine's ProcessBuilder.start at original main-DEX PC 3912. The same coroutine installs a Java Process handle, starts a reader thread, awaits a latch and writes a MutableStateFlow engine state. A Binder response alone is not equivalent.

P47/P181/P182 already preserve the three separate original v138 routes: primary startOrDeny(mode=3), probeBoot -> probeOrDeny(mode=1), runDumpConfig -> configOrDeny(mode=2). All remain DENY, no host ProcessBuilder fallback. Main/probe require merged stderr; config requires split stderr. All need an explicit workdir and PIPE stdin/stdout/stderr. P149 provides an ephemeral HMAC over the complete ProcessBuilder argv, cwd, ordered environment and redirect options. P150 stack inspection is only observation, not authority. P193 previously proved actual Android framework Binder sender UID. P184 previously proved authentic P68 one-use receipt to P75 only for a fixed /system/bin/id -u Android35 test child; it did not run original EngineManager.

## Bounded new code

P194OriginalModeSeal is Java8 preflight with exact builder object identity, caller-thread identity, mode, 64-hex host session, positive owner epoch and invocation sequence, 12-second time cap, immutable P149 HMAC snapshot and one-use/revoke. It fails closed on wrong mode/stderr, non-PIPE redirect, missing cwd, wrong object/thread/session/epoch/seq, modified argv/env/cwd/redirects and replay. First valid or invalid attempt permanently burns the witness; P149 erases secret material. Verification returns void, not a Process or launch permit; there is no ProcessBuilder.start call.

These are NOT unforgeable Android platform credentials. Only a future trusted exact DEX mode-specific host adapter may provide real original coroutine provenance and bind this seal to a P68/P184 receipt. Do not treat JVM caller-supplied mode and epoch as native authorization.

audit_exact_sources.py pins exact existing Git blob SHAs for P35/P47/P149/P150/P68/P75/P184; checks source callsite modes, original Process/latch/state lifecycle edges, P149 HMAC fields and real framework Message.sendingUid receipt checks. It is a SOURCE ONLY audit, not a fresh original APK binary examination. P143/P47 real original-derived DEX CI provides independent earlier binary route proof.

Offline command: bash host_candidate/p194_original_modes/run_java8.sh. Runs P149 HMAC negatives, P182/P183 typed original-gate denies, P194 builder/owner/one-shot negatives and pinned source contract. It never launches Node, arbitrary programs or HTTP, never accesses account data or handles website challenges.

## Blockers and disclaimer

1. Exact original v138 EngineManager start/probeBoot/runDumpConfig process generation and actual coroutine/reader/latch/state-flow wiring to trusted P68/P184/P75 process receipt, without permitting a host fallback.
2. ARM64 original Node + complete read-only FD JS/native graph, genuine token-bearing HTTP READY, then original SessionStore/AgentLoop/ToolRuntime continuity and tool streaming.
3. P102 native UI consent proof is separately blocked: actual Android35 emulator did not show the consent button, dispatch=0, trusted executions=0. Do not bypass. P192 direct isolated TCP BIND_EACCES is a frozen architecture negative; no privileged or SELinux bypass.
4. P47 host launch DENY, P109 native sensitive tools DENY_ALL, GS screenshot OFF, source licenses and fixed-signed data-preserving upgrade remain mandatory. Formal v139=STRUCTURAL_BLOCKED.

Retain original DSHAPP MIT attribution, README/NOTICE and [reference ledger](../../REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md), including independent/nonendorsement and bilingual disclaimers. Shelter GPL concept, gVisor concept, Android AVF/Microdroid future VM, OmniGate browser-life-cycle concept must not be represented as copied code, real phone fingerprint, anti-bot bypass or official sponsorship.
