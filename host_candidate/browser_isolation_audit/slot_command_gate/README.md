# B3: host-owned slot command authorization prototype (test-only)

Pinned MIT DSHAPP v91 source BrowserBridge.kt uses one shared browser-cmd.json
and browser-result.json mailbox with numeric id and arbitrary action. No
profile ID / epoch / one-use request authorization is visible in that v91
path. Signed v138 source is not byte-identical; only the class existence is
attested there. No original browser implementation is modified by B3.

B2 Android35 two-live-process storage proof uses Messenger Message arg1/arg2
PID/UID fields that are caller provided. Those are NOT trustworthy OS caller
identity. Android Binder.getCallingUid is meaningful only while executing the
incoming Binder transaction, not later on a queued Handler. Binder.getCallingPid
is also not a stable security identifier. Same Linux UID processes can share
the app private files and must not be described as adversarially isolated.

This B3 Java-8 host-side policy enforces independent A/B lease objects, owner
epoch, deadline, exact monotonic request sequence, at-most-one in-flight
operation, bounded request/result size, fixed synthetic action allowlist,
one-shot result tickets bound to the original operation and revocation on account switch. Negative tests reject
wrong slot/epoch, duplicate, skipped sequence, expired, replayed, oversize,
cross-slot result, mismatched result operation, forbidden arbitrary JS/file/cookie export, stale response,
and concurrent duplicate requests. Lease/Ticket remain opaque host-only Java
objects; they are NOT IPC credentials and must never enter JS, URLs or files.

STOP: A pure JVM PASS does NOT attest Android Binder framework sender identity,
sensitive output transport, actual v138/v139 BrowserBridge wiring, same-UID
hostile file access, real work profile or AVF/pVM. Next stage requires a
synchronous real Binder transaction framework identity check, bounded IPC,
host-issued account slot/epoch/one-time command capabilities and real Android
negative tests before enabling any production multi-account browser. Preserve
all existing logins, no migrations or data deletion. AI browser deferred.
Sources:
https://developer.android.com/reference/android/os/Binder
https://developer.android.com/reference/android/webkit/WebView

An epoch may only increase for each host-owned slot. Explicit revocation does not
reset the highest accepted epoch: same-epoch reactivation and rollback (ABA)
are denied before replacing an existing lease. This is in-memory for this
disposable gate; production must persist/wrap epochs safely across host restart.
