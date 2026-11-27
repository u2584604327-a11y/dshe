# B1 actual Android35 same-UID process-level WebView storage test

Independent disposable package com.dsh.b1probe, never com.dsh.android.
No INTERNET permission, no user logins, no private files, no screenshots,
no JS bridge or original DSH assets. Never run this script on a phone.

Two non-exported Android Activity processes use a different fixed WebView
data directory suffix before any other WebKit operation in
ProbeApp.attachBaseContext. The controller process disables WebView.
All data are fixed synthetic cookies and LocalStorage on an offline HTTPS
origin whose page is supplied via loadDataWithBaseURL; no Internet is used.

Four cross-process stages in a fresh app: A writes cookie/LocalStorage, B must see neither
and writes its own, A still sees only A, B still sees only B. Missing callback,
stale process, wrong owner/phase, timeout, cookie or LocalStorage mismatch
fails the job. Runtime output is category-only. The runner attests a genuine
fresh Android35 QEMU and refuses preexisting probe installation, installs
and uninstalls ONLY this disposable com.dsh.b1probe test app.

A successful B1 test proves only this Android35 WebView suffix namespace
behaved as expected in this fixture, not production DSH v138/v139 isolation,
not app-UID isolation, not a work profile, not AVF protected VM, and not
IndexedDB/OPFS/ServiceWorker, permissions, downloads, GeckoView, or
cross-process original BrowserBridge ownership. AI browser remains deferred.

After the first A-B-A-B run succeeds, CI explicitly Android force-stops
com.dsh.b1probe, rejects any surviving slot/controller process by name,
then relaunches with a distinct `restart` mode. Slot A and B must retain
only their OWN synthetic cookies and LocalStorage after true process death.
The second run cannot silently write/reseed missing state and has distinct
required log markers. This is **process-restart persistence**, not reboot,
IndexedDB, cross-UID, OS work-profile or VM proof.

### B1 IndexedDB extension

The same four synthetic A/B phases additionally test IndexedDB, not inferred
from Cookie or LocalStorage. A and B first read an empty object store, then
write fixed A/B values. Later reads require the exact own value and deny any
foreign value. IndexedDB asynchronous writes count only after the transaction
commits, and the force-stop/restart pass requires both persisted IDB records.
The Android35 runner fails unless the independent IndexedDB markers for both
the initial A-B-A-B and force-stopped relaunch are present. No JS bridge,
Internet, real browser data, or original DSH application access is added.
Even success is not evidence of CacheStorage, OPFS, ServiceWorker, OS-level
work profile separation or AVF protected-guest virtualization.

The Android35 CI may deliver an emulator startup orientation or UI-mode
configuration transition while the controller awaits each slot. To prevent
an unrelated Activity-recreate from losing the in-memory phase state,
all three test-only Activities lock portrait and declare the same bounded
configuration-change categories as the upstream DSH MainActivity. This
**does not** bypass the existing onCreate(savedInstanceState) rejection,
OS force-stop, exact-process checks or any IndexedDB negative predicate.
An actual process death or unexpected Activity recreation still fails closed.

### Activity re-creation handling (test only)

Real Android may recreate one test Slot Activity because of configuration
or renderer lifecycle changes. The previous instance now invalidates every
outstanding callback on destruction. A recreated Slot performs all cookie,
LocalStorage and IndexedDB validations again using its unchanged phase;
there is **no** restored green result or success token. If a fresh seed had
partially written data, its pre-existing-data checks fail closed. The Main
controller remains strict on unexpected state restoration; the script still
requires distinct current-run proofs and a true OS force-stop/relaunch.

### B2 concurrent live-process extension

After B1 passes, the same disposable app is force-stopped again, without
clearing its synthetic stores. A distinct controller run binds two Android
non-exported Services in :slotA and :slotB **simultaneously**. Each verifies
its original A/B Cookie, LocalStorage and IndexedDB; the controller rejects
identical PIDs, a PID equal to the controller or a UID mismatch. With both
bound processes live, each Service independently updates its synthetic
Cookie, LocalStorage and IndexedDB from A/B to A2/B2 and waits for the
IndexedDB transaction commit, then must read back only its own new value
and never the other slot's Cookie. Binder commands use strict ordered
INIT->WRITE->VERIFY and reject duplicates/out-of-order messages; no user
accounts, private data, external websites, or JavaScript interfaces.

B2 explicitly remains SAME-APPLICATION-UID process-level WebView directory
isolation, not separate Android user/work profile, pVM, or original DSH
browser integration. It does not prove native GeckoView profile isolation,
CacheStorage, OPFS or concurrent cross-UID protection. The next turn should
check true Android35 CI logs before claiming B2 PASS.

### B1 initial Android35 Activity recreation: bounded full-fixture retry

If **and only if** the first disposable `MainProbe` seed run fails with
`B1_ANDROID35_ACTIVITY_RECREATED=DENY` and no other negative category,
the emulator runner may force-stop the **exact** disposable package
`com.dsh.b1probe`, require no remaining B1 processes, clear that
package's synthetic data, create a new unpredictable log boundary,
and re-run the entire fresh A-B-A-B Cookie/LocalStorage/IndexedDB seed
sequence once. This does NOT restore Activity state, reuse earlier
SUCCESS markers or accept the old seed. Any actual storage/cross-slot/
process/UID failure and any repeated Activity recreation fail closed.
All later force-stop persistence and B2 concurrently live-process gates
must still pass in the same new run; original DSH data is never touched.

## B1 Android35 phase-0 synthetic-cookie triage (2026-11-08)

On run #42457706460 the fresh Android35 B1 synthetic fixture failed closed with BOTH `ACTIVITY_RECREATED=DENY` and `PREEXISTING_PROFILE_COOKIE=DENY`. The bounded package-clear retry correctly refused the additional cookie denial; passing prior runs do not override this failure. A synthetically fixed cookie present after Activity recreation is **not** proof of cross-profile leakage or of its originating lifecycle; it may have been written earlier in the same test attempt or may represent a different bug.

The shell runner now reads existing `B1_DIAG_PRESEED_PHASE=0 SLOT=A ...` diagnostics **only after** its unique QEMU current-run log boundary and **only when an existing DENY is present**. It emits fixed enum booleans for whether the initial and recreated phase-0 activity observations contained synthetic slot-A or slot-B cookies. It never prints cookie contents, domain strings, logcat, user data, PIDs, raw phase intents or arbitrary text. Absence is `NOT_OBSERVED`, not silently `NO`. This changes neither the Java test, result admission, bounded retry policy, WebView settings, user account data, nor isolation claims. Both denials remain fatal and the specific `B1_SEED_RETRY_OTHER_DENIAL_PRESENT=DENY` guard stays active. No real phone, original DSH or production APK is touched.
