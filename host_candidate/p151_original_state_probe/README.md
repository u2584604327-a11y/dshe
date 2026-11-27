# P151 — classify why original MainActivity did not reach P47

P150 already verified that the exact signed-v138 original MainActivity
starts on Android35 x86_64, but did not observe a real EngineManager coroutine
at the P47 ProcessBuilder bridge. The previous P43 probe only observed for
about five seconds after Binder HELLO, even though first extraction can
require longer. P151 adds a 40-second **passive** observation window.

P151 only reflects the already-existing original Kotlin EngineManager
singleton; it never calls Companion.get(), ensureExtracted(), preflight,
start(), Java ProcessBuilder.start(), Node or any other tool. At 5/20/40
seconds it reduces the public StateFlow State to enum labels:
IDLE, EXTRACTING, STARTING, READY, FAILED, DEAD, MISSING or UNREADABLE.
FAILED.message is ONLY read within the Java process to classify known
prefixes as TERMUX_NODE_SETUP/NODE_BINARY_MISSING/ENTRY_MISSING/
PROCESS_START/EXTRACTION/OTHER_REDACTED. No raw message, path, argv,
environment, token, URL, user file or stack dump is logged. The original
P150 coroutine hit counter is sampled at 40 seconds separately.

The Android35 x86_64 emulator original package, P43 ephemeral signer and
all P47 no-host-fallback, P109 DENY_ALL and original source resource
hash gates remain unchanged. This is **diagnostic evidence**, not
permission to start Node or proof of production startup. The 40-second
limit may still be insufficient; UNKNOWN/UNREADABLE is NOT a PASS.
No modifications to the user's physical phone, accounts or DSH data.
