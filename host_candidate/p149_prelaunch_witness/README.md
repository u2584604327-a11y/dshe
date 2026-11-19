# P149 — private prelaunch ProcessBuilder HMAC equality witness; production DENY

In existing P47 exact signed-v138 main DEX bridge and the pinned upstream
P142 Kotlin probe/config/main interposition candidate, observe a transient
host-local ProcessBuilder snapshot BEFORE the unchanged intentional DENY.
The same Java 8 implementation serializes, bounds, and HMAC-binds the typed
mode, session, sequence, argv (including patch flags), working-directory
string, complete environment mapping in sorted key order, error merging and
all standard-stream redirect shapes. HMAC secret is SecureRandom-generated
per snapshot, not exported to Node/Binder/logs. The object is consumed once,
fails closed after any mismatch, closes/wipes key and digest, and rejects
bad field encoding, NUL, oversize and replay. No helper executes subprocesses.

CI includes Java8 adversarial tests (argv/cwd/env/stderr/redirect mutation,
wrong mode/session/sequence, reuse, invalid fields), P142 exactly three
pinned source callsites + Kotlin/Java compilation, and disposable
Android35 original-package temporary APK P43 fixture invoking the actual
P40 main-DEX bridge -> P47 -> P149. The latter only proves a **synthetic
P43 ProcessBuilder traversed the pinned original main-DEX bridge**: it does
NOT mean the original EngineManager coroutine supplied real production args.
P142's other two callsites are still sourced from MIT upstream Kotlin, not
actual signed-v138 DEX runtime. The witness is **not** OS caller provenance
nor a trusted independent session authority; it cannot itself approve Node
startup or decide any sensitive tool. No external authorization manifest,
isolated Node loader, EngineManager P37 Process or HTTP URL token Ready.

P47/P142 continue to throw intentional no-host-fallback exceptions;
P109 native sensitive execution DENY_ALL, v139 release BLOCKED, no
same-signed APK, no user phone/account state touched. Next high-value
gate: produce a trustworthy original-v138 EngineManager-generated builder
on an emulator, prove its OS source and actual callback lifecycle, and
bind independent Broker authority before any isolated production launch.
