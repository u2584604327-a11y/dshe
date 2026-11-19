# P310 — Android 35 ART package 'verify' smoke, never a release gate

P309 passed same-original-app original archive FD + host loopback + P37
real child receipt on real Android35 x86_64; that child was fixed
`/system/bin/id -u`, NOT the original ARM64 Node.

This P310 is a NEW, more relevant gate for the former P245 source-only
candidate: reproduce the exact P294 disposable DEX with temporary P245
helper and P279 string reuse, unmodified P43 baseline, verbatim classes3
and validated binary-AXML Manifest. Explicitly check the **unchanged**
original P245 verifier still rejects the candidate with its former
rendered-text `HELPER_TYPED_READ_AND_CATCH` (expected rc=2); require the
independently source-SHA-pinned P291 strict cloned verifier to pass
against the *same* candidate DEX. The original P245 source is untouched.

Sign with a new one-day private throwaway key differing from the original
signer. Install only into a fresh **Android 35 x86_64 CI emulator**;
forbid app launch, enforce app UID IPv4+IPv6 egress DENY; request
`cmd package compile -f -m verify com.dsh.android` and require
command 'Success'. Check that no app process was launched. This
observes package-manager ART verify-mode acceptance, NOT complete
individual class verification or original EngineManager execution.
No DEX, APK, keys, logs are distributed. Destroy all scratch.

A failed APK install/verify, wrong DEX, missing P291 strict pass,
wrong P245 deny, permission policy mismatch or changed original
SHA -> fail closed. Do not change P245/P192/P47/B3/B4 or auto-accept
Android licenses. Real ART class-loading, ARM64 runtime, original Node
dynamic linking, original EngineManager handoff, host-only token READY
and production account isolation remain NOT ATTESTED. v139 BLOCKED.
