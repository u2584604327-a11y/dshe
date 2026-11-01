# P147 — one bounded in-package relative import candidate, second original TAR pass
P146 classifies literal import hints in the exact original CLI `node_modules/@deepseek-ai/dsh/lib/bin.js`.
P147 chooses the first eligible in-package JS/JSON filename present in the
exact verified original TAR member set (not a Node resolution oracle). Within
the same authenticated isolated Android UID and session, duplicate the same
read-only, unlinked original archive FD, rewind the duplicate, re-read and
fully hash the entire original immutable 30,411-member TAR tree, then release
only the exact chosen candidate (<=512KiB, SHA-256 checked, once). Zero its
byte buffer before returning; do not send source or member names in Binder
ACK or logs. Original P143-P146 all remain mandatory. Missing/unresolvable
relative source causes P147 to fail closed, never synthesize a module.

This is intentionally not an npm/Node resolver: regex literal discovery can
include comments, exclude nonrelative imports or miss dynamic/conditional
imports, package exports, native addons and transitive imports. A PASS proves
source-byte retrieval of one bounded *candidate*, not a real Node dependency
edge or full module graph. No app-private files, user credentials, JS execution,
EngineManager process handoff, native .node dlopen or HTTP/token READY. P47
no host fallback, P109 sensitive tools DENY_ALL, ephemeral emulator-only APK,
v139 formal BLOCKED.
