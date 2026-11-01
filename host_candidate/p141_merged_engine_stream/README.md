# P141 Original EngineManager redirectErrorStream(true) adapter

User's real-device P139/P51 shows the original v138 Node fixed synthetic test
ran under a separate app's Android isolated UID; not production EngineManager.

Original pinned MIT EngineManager starts with ProcessBuilder.redirectErrorStream(true).
P37 previously offered only separate stdout/stderr. This patch provides an
opt-in Boolean *trusted constructor* on the existing P37, P67 and P68 class
chain. Their pre-existing constructors delegate with false, keeping P51/P48
tests unchanged. The new mode unifies authenticated stdout and stderr frames
in order into one bounded stdout buffer and immediately closes the error
stream to EOF, matching redirectErrorStream(true). P53 sequencing, Android
framework sendingUid verification, session, replay, terminal exit, stop/
revoke and overflow checks are retained; no text-based READY assertion.

No Binder Bundle may select stream merge mode. It is **not enabled** by
existing P48/P51 callers; a future same-package trusted EngineManager
broker must choose it only when matching original ProcessBuilder semantics.
The existing P74/P75 fixed /system/bin/id fixture remains unmodified and
cannot grant original Node argv, scripts, private paths, credentials or tools.

This is an authentic runtime transport component with compiled JVM tests and
SDK35 verification; it is NOT a full production EngineManager patch. P109
native sensitive tools stay DENY_ALL and formal fixed-signed v139 remains
BLOCKED. No APK or original user-device changes.
