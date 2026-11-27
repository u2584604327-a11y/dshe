# P200 — exact pre-MainActivity baseline to original framework onCreate/onResume

This phase closes the **P199 three-second blind spot**. P199 launched the original MainActivity first and did not snapshot P150's original coroutine stack-shape counter until after that startup, leaving a possible early call undiscovered.

## What P200 actually does

1. Build a disposable original-signed-v138-derived test APK with the **original MainActivity, EngineManager, P150/P151, resources, native libraries and classes2.dex preserved** and P47 three original spawn routes DENY. Never use the original signing key, change its package on a user's phone or distribute the temporary test APK.
2. Fresh Android35 emulator, original DSH package not installed, outbound app UID IPv4+IPv6 traffic blocked. First launch **only** an ADB-only disposable P43 test Activity with explicit `p200_prelaunch_window` flag. Its CI-only branch registers `Application.ActivityLifecycleCallbacks` and records the **existing** P150 original/synthetic counter values and P151 original state before original MainActivity startup. It explicitly does **not** invoke the P43 synthetic P40 bridge, P43 Binder, original EngineManager.start, Node or native tools.
3. CI waits for a unique current-run prelaunch baseline marker and ensures the prelaunch app process exists. Only then does it launch the manifest's **unmodified original launcher Activity**. It checks that the process ID stays identical, and the real Android framework notifies the registered callbacks for that original Activity's `onCreate` and `onResume`. Observe P150 counter delta at both edges and t=0/2/5/10 s after real onResume, along with finite P151 state categories and exact existing EngineManager singleton pointer identity. No original process streams, private state text or user data is read.
4. The fixed status result is one of `P200_ORIGINAL_START_PRELAUNCH_TO_10S=OBSERVED_NON_AUTHORITATIVE` or `NOT_OBSERVED`. **Either can satisfy the *measurement* acceptance** if the actual framework callbacks, same-PID proof, and four samples all occurred. A nonzero P150 counter is only a stack-shape observation, not a trusted coroutine/OS owner receipt. A negative means no P150 hook invocation in this bounded pre-launch-to-post-resume window, not proof of permanent absence.
5. All identity drift, unexpected lifecycle sequence, missing App framework event, changed existing singleton, unexpected original state enum, stale/missing marker, emulator reboot or duplicate test is rejected. Runner prints only fixed status labels; never raw logcat, Activity class details, numeric UID/PID, IP, original code strings, token or launch command content.

## Crucial limitation

To register lifecycle callbacks **before** original MainActivity launches, P200 first starts the test-only Activity in the original app process. This constructs the original `Application` and loads the app process **before** the original MainActivity. This is a *pre-MainActivity* observation, **not an entirely unmodified cold process bootstrap**. An original EngineManager call made during Application initialization can still precede the baseline. The next investigation should use P198's four real signed-DEX `EngineManager.start()` direct callsites and real UI event sources, rather than fabricate a call or unmask live private application state.

A real original coroutine, original Process field/reader thread/CountDownLatch/StateFlow paired lifetime, P184 receipt to the genuine Kotlin coroutine and authenticated ARM64 Node/FD native module/JS/Bearer HTTP READY are all **not yet proven**, regardless of a positive or negative P200 counter. P47 always rejects launch with no host ProcessBuilder fallback. P192 isolated UID direct localhost TCP BIND_EACCES remains a security boundary; P102 native approval must be human-entered, never synthetic.

No production deployment, signed v139 APK or user-phone install is authorized. GS screenshots OFF and P109 native-sensitive tools DENY_ALL. BrowserLeaks, original CreepJS GitHub Pages, IPhey, BrowserScan, EFF Cover Your Tracks and AmIUnique remain manual opt-in privacy QA references; no CI external-site visits or fingerprint spoofing. Keep original DSHAPP attribution, MIT notice and nonendorsement ledger. v139=`STRUCTURAL_BLOCKED`.

## 2026-11-08 strict duplicate-creation triage (test-only)

The actual Android35 P200 run
https://github.com/u2584604327-a11y/dshe/actions/runs/42398154690
proved a fresh original-derived test package, no external egress,
pre-MainActivity baseline and same host process, but failed closed at
`P200_ORIGINAL_LAUNCHER_DUPLICATE_CREATE=DENY`. That category alone does
not prove a second original EngineManager startup.

The CI-only lifecycle observer now logs a fixed, non-sensitive category
for the second framework onCreate: `SAME_JAVA_INSTANCE`,
`RECREATED_AFTER_DESTROY` or `NEW_WHILE_OLD_ALIVE`; plus YES/NO for
the first instance's save-state and stop callbacks. It **still always**
calls `fail("ORIGINAL_LAUNCHER_DUPLICATE_CREATE")` with no permit, auto-
retry, extra Activity launch, external network, lifecycle override, or
original bytecode change. On any duplicated activity the CI remains red.
Never use this classification as a security authorization. This work
does not attest original Node, P209 coroutine, process owner epoch, or
an actual browser/account isolation boundary.
