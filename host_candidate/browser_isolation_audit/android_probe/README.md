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
