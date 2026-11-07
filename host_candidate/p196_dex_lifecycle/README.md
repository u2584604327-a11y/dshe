# P196 — exact signed-v138 vs ephemeral P47 DENY DEX instruction parity

Scope is the **sole** u2584604327-a11y/dshe Draft PR #80 and existing branch. This is a **read-only binary comparison**, not a runtime proof or a grant to execute original Node. No production data, signing key, release or phone is used.

## Strict input and provenance

- The baseline APK must have exact SHA256 \`3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5\` and bounded original size. Download only the fixed release asset already used by the P43/P143 CI build, and leave it in temporary runner storage.
- The comparison target is the same original-v138-derived temporary \`com.dsh.android\` test APK, with P40 primary bridge and P47/P181/P182 **all-three DENY** routing. Production original package, installed user data and native libraries remain untouched. The test archive uses a short-lived disposable signer and is **never distributed**.
- Parse actual \`classes.dex\` from both APKs with pinned androguard 4.1.4. Require exact method identity, original bytecode PC, instruction width, symbolic operands, same registers/ins/outs, same try-span and resolved catch handlers (compare *type names* not unstable type indexes).
- In \`EngineManager$start$2.invokeSuspend\`, the sole allowed difference is the original PC 3912 six-byte \`invoke-virtual ProcessBuilder.start()\` becoming the exact P40 \`invoke-static start(ProcessBuilder)\` using **identical register operands**. The original Process field assignment PC3924, Thread constructor PC3986, thread.start PC4010, CountDownLatch await PC4026 and StateFlow.setValue PC4674 must be present identically. The PC3980 coroutine continuation is also pinned.
- In \`EngineManager.probeBoot\` and \`EngineManager.runDumpConfig\`, allow exactly one corresponding original \`ProcessBuilder.start()\` → P40 \`probeOrDeny\` / \`configOrDeny\` redirection. Their exact original PCs are discovered only from the pinned DEX; everything else must compare identical. P47's existing verifier separately demands the typed P40 bridge and P47 DENY path for each mode.
- Any other opcode, register, branch, try-range, catch type/handler, method signature, bytecode width, changed variable/constant/field, extra callsite, missing method, modified \`classes2.dex\`, changed \`assets/\` or \`lib/\` bytes, corrupt ZIP or unknown decoder state **fails closed**. No broad whitelist, no approximate decompilation.
- On failure, print **only** a bounded category/method/PC; never log private original command argv, cwd, environment, DEX string constants, cookie or user's secrets. On success, output only method labels, replacement PC and instruction *counts* in an ephemeral redacted JSON report. No secrets or original APK are uploaded as Artifacts.

## Commands and limits

\`python3 host_candidate/p196_dex_lifecycle/test_symbolic_diff.py\` performs source-only synthetic negative tests and does not require androguard or a baseline APK.

With disposable test files already present, execute:

\`python3 host_candidate/p196_dex_lifecycle/audit_exact_v138_dex.py ORIGINAL.apk DERIVED.apk --report .p196tmp/safe-summary.json\`

A passing P196 audit proves only **the three original methods' decoded symbolic instruction parity and protected APK resource parity**. It does not prove:
- real original Kotlin coroutine ran (P150 stack observation is non-authoritative),
- P184's real authenticated Android UID receipt has been delivered to *that* original coroutine,
- original ARM64 Node/FD JS/native workspace, HTTP token READY, real StateFlow and reader/latch runtime parity,
- native UI user consent, signing or real upgrade, Android full VM or anti-abuse bypass.

P193 host-owned localhost with genuine Binder Message.sendingUid and replay denial **already passed** real Android35 CI #41939260439. P184 same-UID receipt with fixed \`/system/bin/id -u\` child passed prior Android35 CI #41855844987. Never confuse these synthetic test paths with a production Node / model request. Old P192 isolated UID TCP \`BIND_EACCES\` remains negative architectural evidence.

Preserve P47 host ProcessBuilder fallback DENY, P109 native sensitive tools DENY_ALL, GS screenshots OFF, human-only website verification without IP/account/UA/fingerprint rotation, original DSHAPP MIT credit and bilingual unofficial-modification disclaimers from [reference ledger](../../REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md). Formal v139=STRUCTURAL_BLOCKED.
