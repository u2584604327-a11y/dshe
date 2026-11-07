# P143 same-package original engine.bin FD transfer, nonproduction

P43 original com.dsh.android actual APK previously bound a non-exported isolated Service;
P76 side-by-side P51 app previously demonstrated SHA-bound original engine.bin
read-only, unlinked file descriptor and P77/P78 TAR+one JS module verification.
This changes only the temporary P43 test Activity host package admission to also
allow original com.dsh.android in disposable CI emulator. Only P43ProbeActivity
can invoke the method, with host UID matching its Android ApplicationInfo.
The existing P51 sidecar path retains its original checks.

The ephemeral exact original v138-derived app undergoes full asset/hash check,
P47 main-engine no host fallback, manifest non-exported isolated service check,
and real Android 35 x86_64 Binder transfers original GZIP bytes in a read-only
unlinked FD. P77 validates original 30,411 TAR member tree; P78 securely
reads a bounded JS module once without ever loading or executing it.
No original Node production startup or SessionStore readiness is claimed.
The runner verifies ro.kernel.qemu=1 BEFORE uninstalling any package;
this script must never run on the user phone, and no APK is published.
No SDK license acceptance is automated; P109 remains DENY_ALL.

P143 is a true original-package resource transport gate, not a production
EngineManager Broker. Real script loader, scoped argv/env/cwd mapping and
P37 Process handoff/real token URL readiness still block v139.
