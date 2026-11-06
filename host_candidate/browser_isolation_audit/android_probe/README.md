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
