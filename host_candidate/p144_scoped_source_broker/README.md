# P144 — exact original archive, two scoped source leases (emulator gate)

P143 already demonstrated original com.dsh.android package Binder to an isolated
UID, pinned original engine.bin FD, P77 full canonical TAR validation, and a
single P78 JS read. P144 adds a second bounded resource path inside that SAME
authenticated isolated session. It selects the first eligible <=64KiB JS
source and the first eligible <=32KiB package.json from the complete original
archive, retaining only two in-memory buffers. They are sealed ONLY after
P77's 30,411-member original tree fingerprint matches exactly. Both use opaque
path-derived IDs and content digests. The worker consumes each once under
the authenticated session and verifies SHA-256; the broker zeroes both buffers
on close. No arbitrary paths, per-request host filesystem reads, raw JS in
Binder ACK, generic directory mappings, or archive extraction.

P144 is an original-source multi-resource transport primitive, not proof that
the selected package.json is an actual dependency of the selected script.
Node's dynamic module resolver, real production entrypoint, native .node
Bionic compatibility, EngineManager argv/cwd/env, process facade and HTTP Ready
are NOT wired. P47 prohibits host ProcessBuilder fallback, P109 keeps sensitive
tools DENY_ALL, the disposable unsigned/ephemeral test APK is never released,
and the user's installed original package is not changed.

P144 acceptance: Android 35 disposable emulator must report both
P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES=PASS and
P144_ORIGINAL_SCRIPT_AND_PACKAGE_BYTES_ISOLATED=PASS, plus all existing P143
and P47 invariants. Any missing member, tree drift, unrecognized worker UID,
session mismatch, oversize lease or invalid digest is a STOP. No formal v139.
