# B0 — browser data isolation and verified virtualization boundaries

Priority: browser identity/data safety first. AI browser model integration is DEFERRED.
This is a read-only assessment, not a profile manager or virtual machine.

## Concrete upstream source evidence (NOT assumed byte-identical with v138)

Public MIT DSHAPP source pht88888888/DSHAPP at commit
4dddb12fd076d052e788a16638a658b7a447b669 (versionCode 91):
- AiBrowserView.kt explicitly documents that its separate WebView instances use
  the same WebView data directory and hence share cookies with the official UI.
  Its setup uses CookieManager.setAcceptCookie(true) and
  CookieManager.setAcceptThirdPartyCookies(wv, true).
- BrowserBridge.kt uses the shared browser-cmd.json / browser-result.json
  files below one DSH home; its mailbox is not a per-profile authority.
- MainActivity.kt creates AiBrowserView in the main Activity process.
- DshApplication.kt recognizes many Gecko subprocesses; "unknown process"
  can fall back to main-process treatment, unsuitable for a new isolated
  browser process. Changing that without full boot regression review is unsafe.
- This upstream is v91; user's signed v138 is different. Only the B0 DEX
  scanner probes *actual SHA-pinned signed v138* direct Java/WebKit API calls.
  It never reads browser cookie values or runs the APK. Reflection, native
  calls, Android process configuration and runtime profile identity remain
  unproven. No one may claim L1/OS/VM isolation from these static counts.

## Enforcement level must be stated truthfully

L0 / same-process tabs or WebView objects: NOT independent profiles.
CookieManager is per WebView browser-process data directory, and ordinary
tabs do not get distinct localStorage/IndexedDB/ServiceWorkers by account.
Changing UA, clearing one tab, or switching an on-screen account selector
does not provide persistent cross-account data isolation.

L1 / process-specific WebView data directory: each fixed Android process
has one stable unique setDataDirectorySuffix configured before *any* WebKit
initialization, with explicit manifest process routing and fail-closed slot
ownership. Different Android processes must not open the same data directory.
Android's documented API can separate profile cookies/cache at this level,
but the APK's processes still share Linux UID/private files and are NOT a
separate Android security principal or hardware VM. Same-process hot switching
is not supported. Do NOT copy cookies from one suffix to another, silently
reset WebView data, or claim that duplicate WebView instances suffice.

L2 / distinct Android user or work profile: only with a real OS-managed
different userId/application UID, storage and cross-profile Intent/URI policy
verified on-device with the user's explicit setup/approval. No automatic
device-admin enrollment, root, Shizuku access or silent app/user migration.

L3 / AVF pVM: only when the device's actual virtualization support,
permissions, protected guest boot, image identity and host-guest isolation
are proven. Microdroid is not automatically a complete interactive Android
browser or second phone. P51 isolatedProcess, a Linux ARM64 CI host, QEMU,
WebGL substitution, guest-looking UA or WebView suffix are NOT pVM evidence.
No AVF support -> honestly mark VM UNAVAILABLE; do not spoof virtualization.

Sources: https://developer.android.com/reference/android/webkit/WebView
         https://source.android.com/docs/core/virtualization
         https://source.android.com/docs/core/virtualization/security
         https://developer.android.com/work/managed-profiles

## Security test matrix, with STOP conditions

1. Original v138 SHA/binary source + manifest process model audited. Zero
   copies of user data, APK not executed; unchanged source must not be
   falsely classified as v91 behavior without independent DEX evidence.
2. Independent process test on disposable Android 35/36 APK: fixed slot A
   creates same-origin cookie, LocalStorage, IndexedDB, cache/ServiceWorker
   and (where supported) OPFS; slot B and main UI must be unable to read
   them in *both directions*. Test simultaneous slots, process crash/restart,
   reboot, persistent restore, slot deletion/recreation and stale tasks.
3. Direct CookieManager, WebStorage, ServiceWorkerController, WebView cache,
   HTTP auth, certificate, permission and JS bridge ownership scoped to the
   right process. Third-party cookies default DENY in isolated slots unless
   specifically user enabled for that slot. No account data passed by intent,
   JS request, URLs, Binder, screenshots, logs, diagnostics, clipboard,
   downloads, SAF URIs, browser command/results or SharedPreferences.
4. Cross-process command interface must independently authenticate actual
   Android Binder sendingUid and a host-generated exact profileId/lease,
   generation, expiry, sequence, request limits, replay denial and revocation.
   Same UID on different processes is NOT sufficient to distinguish profiles;
   explicit process-specific authority is mandatory.
5. Work profile proof: distinct real Android userId/UIDs and storage, with
   cross-profile communication denied or explicitly user approved.
6. pVM proof: genuine protected guest, verified integrity and memory/FD/vsock
   boundary, guest disk wipe, lifecycle/epoch and failure recovery; never
   describe a WebView or isolated service as a VM.

Only after all required matching-level gates and no-data-loss migration
succeed may the UI label a profile as "isolated" at that specific level.
A profile chooser must display "NOT ISOLATED / UNAVAILABLE" when no
verified slot exists, and reject selection rather than reuse the current
cookie jar. Never delete or overwrite the installed signed original DSH to
test a new isolated flavor. Preserve existing logins by default, freeze AI
browser expansion, keep P47/P181/P182 DENY, P109 DENY_ALL, GS OFF.

Current release status: B0 BINARY_AUDIT_PENDING until exact SHA CI, L1/L2/L3
NOT_ATTESTED, DSH v139 STRUCTURAL_BLOCKED. No production APK.
