# DSH v139 P2+P6 real baseline preflight — 2026-10-29

## Primary verified run

GitHub Actions run: https://github.com/u2584604327-a11y/dshe/actions/runs/40812133057

Status: **SUCCESS**. This run reads existing signed v138 APK and P6 Release sources, but **never generates a modified APK or installs anything**.

### Verified input identity

- Repo: `u2584604327-a11y/dshe` (private).
- v138 input: `DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk`, SHA256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`.
- P6 input: `DSH_V139_P6_NODE_CREDENTIAL_LOG_REDACTION_AND_ASSET_STAGING.zip`, SHA256 `3af586c2c83d1aea67d119357672559eb09371c77ef4e06900bb697c06d11fd5`.
- Original v135 and v138 package identity, v2 signature and fixed certificate were previously verified in https://github.com/u2584604327-a11y/dshe/actions/runs/40810972896

### Native bounded DEX static verification

Current private files:
- `host_candidate/patch_deny.py`
- `host_candidate/patch_browser.py`
- `host_candidate/patch_privacy.py`
- `host_candidate/verify_p2_scope.py`

The workflow **replays** four diagnostic-deny methods, two browser getter/open methods and one WebView configuration method from the exact v138 `classes.dex`, entirely in memory.

- Combined target DEX SHA256: `9a7cd89f4a5c86394770febf703a9345a44d8c12c39abec9d494635587d8f221` — PASS.
- 7 targeted original method bodies — scope PASS.
- 52,004 other code method bodies unchanged — PASS.
- Only expected DEX header integrity fields and target instruction ranges changed — PASS.
- Reconstructed instructions, preserved code headers/handlers, DEX SHA-1 and Adler32 — PASS.
- No new DEX references — static scope PASS.
- **New signed DSH APK built: NO**.

This is **not** a run of these bytes under Android ART or a true connection of P5's new Java classes into the existing Android host. Four original upload-entry denials do **not** cover generic native uploads or arbitrary Node diagnostic-sending paths.

### P6 asset preimage compatibility

Current private verifier: `host_candidate/verify_p6_asset_preimages.py`.

The workflow compares these three v138 ZIP entries with the P6 overlay manifest, both by exact SHA256 and byte length:

- `assets/browser-tool.zip` — PASS.
- `assets/browser-pane.zip` — PASS.
- `assets/dsh-fetch-guard.mjs` — PASS.

All three replacement assets match their pinned P6 hashes; nested browser ZIP CRC checks PASS. This proves **static asset replacement compatibility**, not that a running DSH host loads the replacements or fixes the visible UI.

### CI artifact storage

One preceding CI run had `P2/P6` checks PASS but the final artifact upload failed because the GitHub Actions **artifact storage quota was exhausted**. The final successful workflow writes textual hashes and gating status to the job summary instead, with **no artifact upload**, and requires no additional user files.

## Remaining release blockers

| Gate | Status |
| --- | --- |
| Exact baseline inputs | PASS |
| v138 P2 bounded DEX candidate static replay | PASS |
| P6 three-resource overlay preimages | PASS |
| P5 single-use safe sender hooked into real native transport | NOT_IMPLEMENTED |
| Native and Node diagnostic sending fully closed against bypass | NOT_VERIFIED |
| Native user review dialog hooked to existing log UI | NOT_IMPLEMENTED |
| Device settings button attached to original browser title bar | NOT_IMPLEMENTED |
| viewport/DPR/UA real application and readback | NOT_VERIFIED |
| Separate browser profile, cookies and storage verified | NOT_IMPLEMENTED |
| Runtime JS asset migration into full original host | NOT_VERIFIED |
| VersionCode >138 APK build | NO |
| Original-certificate v139 signing | NO |
| Android ART, data-preserving offline install and real phone | NOT_VERIFIED |

**Do not sign, publish or install a new APK based on the static replay alone.** Keep original signing material out of GitHub and the existing phone v138 unchanged. The next required engineering work is *actual native/Node send-path integration* and *Android host UI integration*, which cannot be accomplished by merely appending the existing standalone Java classes to DEX.

## Native diagnostic upload call-graph and egress delta (verified 2026-10-29)

### Read-only original DEX invocation analysis

Source: `host_candidate/audit_native_upload_callgraph.py`

Verified GitHub Actions: https://github.com/u2584604327-a11y/dshe/actions/runs/40813846052

- 4,599 DSH application method implementations scanned.
- 6,149 direct app-to-app invocation pairs identified.
- 56 app-code direct calls to network-related Java APIs. These are **not** 56 confirmed diagnostic upload paths.
- Static audit detects 22 `LogUploader` method definitions and their caller sites.
- Confirmed original upload path: `LogViewerActivity.upload$lambda$49 → LogUploader.upload → upload$lambda$12 → doUpload`.
- Confirmed legacy retry path: `DshApplication.uploadPendingBundles → retryPending → retryPendingLocked → doUpload`.
- `doUpload` invokes `HttpURLConnection.getOutputStream()`; it is a concrete original native send sink.
- `LogCommandBridge` local export and `LogUploader.enqueue` are not by themselves evidence of a network request.

### Real DEX patched sink removal

Source: `host_candidate/verify_diagnostic_egress_sites.py`

Verified GitHub Actions: https://github.com/u2584604327-a11y/dshe/actions/runs/40814002535

- Original v138 exact SHA256: `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`.
- P2 in-memory candidate exact `classes.dex` SHA256: `9a7cd89f4a5c86394770febf703a9345a44d8c12c39abec9d494635587d8f221`.
- Original diagnostic-focused classes contained **5** direct HTTP/URL sink instructions (constructor, `openConnection`, `setRequestMethod`, `setDoOutput`, `getOutputStream`).
- P2 candidate contains **0** such direct sink instructions in the same classes: **PASS**.
- Full P2 seven-method byte-range and non-target method invariants: **PASS**, verified separately in the same run.
- P6 static three-file overlay preimages: **PASS**.

**Limitations:** This shows removal of the known native diagnostic uploader HTTP implementation from a validated *uninstalled candidate DEX*. It does not exclude generic native bridge, reflection, JNI, additional HTTP libraries, Node outgoing requests, or other executable/network transports. It does not implement P5's approved transport and native review UI. The candidate DEX was never written into a signed APK and was not executed on Android ART.

- KNOWN_NATIVE_DIAGNOSTIC_HTTP_SINK_REMOVED_IN_CANDIDATE: **PASS**
- ALL_NATIVE_NODE_EGRESS_CLOSED: **NOT_VERIFIED**
- NATIVE_APPROVAL_UI_CONNECTED: **NO**
- DSH_V139_APK_BUILT: **NO**
- ART_AND_REAL_PHONE: **NOT_VERIFIED**
- PHONE_V138_CHANGED: **NO**

Do not upload signing material to GitHub or install/debug the current v138 online with sensitive data. The required next implementation is a controlled Android host path that routes all diagnostic send requests through the native per-bundle review and fail-closed transport, with isolated ART and offline device verification before signing.

## P5 Android native compilation + P2/P5/P6/P7 unsigned fusion (2026-10-29)

### Android-native compilation

PASS: https://github.com/u2584604327-a11y/dshe/actions/runs/40814642663

- All nine P5 Java sources from the **pinned** P6-embedded P5 archive compiled against Android API 35 using Java 8 language compatibility.
- D8 compiled them for Android minimum API 26.
- **63 P5 class definitions** in the resultant component DEX, including compiler-generated nested classes.
- No native Activity was wired into the installed original app and no ART execution happened.

### Fusion into one temporary UNSIGNED APK structure

P2+P5+P6 PASS: https://github.com/u2584604327-a11y/dshe/actions/runs/40814995654

P2+P5+P6+P7 PASS: https://github.com/u2584604327-a11y/dshe/actions/runs/40815688204

The private workflow dynamically downloads the exact v138 signed APK and exact P6 ZIP, replays the seven bounded P2 changes, compiles the nine P5 sources into `classes3.dex`, replaces three P6 assets and adds P7's narrowed `assets/logs-tool.zip` asset.

For the final P2+P5+P6+P7 **ephemeral unsigned** experiment:

- SHA-256 of bounded main DEX: `9a7cd89f4a5c86394770febf703a9345a44d8c12c39abec9d494635587d8f221`.
- SHA-256 of P5 additional DEX: `552d593f42596a624b36374243f48aec10ffec6a9006eaa1b4974bc84ffab56b`.
- P5 definitions added: **63**, and class descriptor collision with original two DEX files: **none**.
- P7 logs-tool replacement SHA-256: `71c92b1ec4facad6d443d3277e72303684751dc9f5ce44481db6aeb582082d58`.
- Original file entries verified byte-for-byte unchanged: **965**.
- Temporary unsigned, pre-zipalign APK SHA-256: `5643d1364d61bd447a3776f01edcb30982a0f288ea8719b126932726c91afdd5`.
- Temporary unsigned APK size before alignment: **147,382,039 bytes**.
- Android `aapt`, `zipalign`, ZIP CRC and DEX entry structural checks: PASS.
- APK original signature intentionally **invalidated** by repacking and the job requires `apksigner verify` to reject the result.
- The temporary APK was deleted on the GitHub Runner; no APK file was uploaded to Actions Artifacts or GitHub Releases.
- `versionCode` stays **138**, because this is a lab structure, not an approved v139 installation candidate.

### P7 Node diagnostic export AI-output containment

PASS: https://github.com/u2584604327-a11y/dshe/actions/runs/40815619962

Source: `host_candidate/patch_logs_export_output.py`.
Synthetic native mailbox regression: `host_candidate/test_logs_export.mjs`.

The original `logs` tool's `action:"export"` returned an absolute `bundlePath` and told the model it could send that ZIP. P7 still allows the native host to generate a local bundle, but exposes only a bounded success/failure, optional bounded byte count, and a requirement for native review. It drops the original mailbox's path, message, nested `details` and any synthetic sensitive canaries from **the model-facing result**. Other `summary` behavior was exercised and preserved. P7 is only in the **unsigned lab**; installed v138 is unchanged.

**Critical limitation:** the native mailbox itself can still contain a path. Node shares the application's UID and may access the private files directly; generic file transport or shell tools may bypass a model-output-only restriction. Neither P7 nor P5 adds a strong Node filesystem capability boundary. A reliable total diagnostic egress policy requires an isolated process/UID or a native-controlled private queue inaccessible to generic tools and enforcement at every diagnostic-capable transport. A separate user-approved sharing UI must be connected to the host to permit safe intentional sends. Do not assume unchanged ordinary attachments are blocked.

### Release blockers and next engineering requirements

- HOST_NATIVE_DIALOG_CONNECTED: **NO**.
- P5_TRUSTED_SINGLE_USE_TRANSPORT_CONNECTED: **NO**.
- LEGACY_NATIVE_AND_NODE_DIAGNOSTIC_EGRESS_TOTAL_GATE: **NOT_VERIFIED**.
- GENERIC_NODE_FILE_ACCESS_ISOLATION: **NOT_IMPLEMENTED**.
- STORAGE_AND_COOKIES_ISOLATION: **NOT_VERIFIED**.
- ART_RUNTIME_LOADING_TEST: **NOT_RUN**.
- VERSIONCODE_139_SIGNED_WITH_FIXED_CERT: **NO**.
- DATA_PRESERVING_DEVICE_INSTALL: **NOT_TESTED**.

**Do not sign, publish or install the ephemeral assembly.** It is not a ready APK, and no original fixed signing private key should be uploaded to GitHub. Continue with real native host invocation and Node process capability boundaries, not only more standalone JVM tests.

## P8 native mailbox path containment and disposable Android test (2026-10-29)

### Verified P8 native DEX modification

Source: `host_candidate/patch_native_export_reply.py`. Real v138+P2 in-memory replay: https://github.com/u2584604327-a11y/dshe/actions/runs/40817557005

The original `LogCommandBridge.doExport(Lorg/json/JSONObject;)V` (code offset 3,287,332) invokes `File.getAbsolutePath()` and writes `bundlePath` into its JSON reply. This was verified independently in https://github.com/u2584604327-a11y/dshe/actions/runs/40817381857.

P8 replaces four exact bytecode instructions at absolute DEX byte offsets **3,287,476–3,287,494**, 18 bytes total, with nine NOP code units. It preserves the original `DiagnosticBundle.build` call and bundle-size `JSONObject.put` operation. All other code method bodies remain identical and no new DEX refs were added. The full original v138 ZIP was kept intact; no signed update has been published.

- P2 combined DEX SHA256: `9a7cd89f4a5c86394770febf703a9345a44d8c12c39abec9d494635587d8f221`
- P2+P8 combined DEX SHA256: `d7a984597930c7599732d3d5c87df61d15c80bc4a1a942f0fd4d6db7dc2355b3`
- `NATIVE_EXPORT_REPLY_BUNDLE_PATH_REMOVED=PASS_STATIC`
- `ORIGINAL_DIAGNOSTIC_FILE_CREATION=UNCHANGED`
- `P7_NODE_AI_VISIBLE_PATH_REDACTED=PASS_SYNTHETIC`
- `NODE_SAME_UID_FILESYSTEM_ACCESS=UNRESOLVED`
- `P8_ART=NOT_VERIFIED`

### Disposable Android ART test — evidence boundary

A separate private Actions workflow builds the P2–P8 *lab only*, with a fresh non-original ephemeral signing key generated inside the runner, no GitHub artifact upload or GitHub Release, and a new offline emulator.

- The P2–P7 iteration at https://github.com/u2584604327-a11y/dshe/actions/runs/40817134153 **installed successfully** on Android 35, but the test's implicit `MAIN/LAUNCHER` intent did not resolve. No app-start or ART execution PASS was claimed. The signing key and APK were deleted.
- The follow-up P2–P8 iteration at https://github.com/u2584604327-a11y/dshe/actions/runs/40817726760 adds offline `cmd package compile -m speed -f`, then checks a manifest-derived explicit Activity or `com.dsh.android.MainActivity` and monitors fatal errors. Its actual Actions result must be consulted independently before recording an ART PASS.
- Android lab certificates **differ from** the original fixed signer, so this cannot upgrade the installed personal v138 app and must never be distributed as a real APK.

### Native browser IllegalAccessError constraint

Verified read-only two-DEX audit: https://github.com/u2584604327-a11y/dshe/actions/runs/40816918553. The original `AiBrowserView.currentWebView()` is `private final` (`0x12`) and has 18 `invoke-direct` calls, none directly from `BrowserBridge` in either original DEX. Blindly changing it to public would require modifying the call instruction types and is **not an authorized bounded fix**. No such potentially unsafe flags were changed.

**Still blocked:** actual P5 native UI-to-legacy Activity wiring, default-closed one-shot transport integration, Node privilege/UID filesystem bypass, storage isolation, original-certificate v139 signing, and data-preserving real-phone upgrade. Never mark the temporary lab APK ready to install.

## ART-safe replacement: Android 35 emulator launch PASS (2026-10-29)

The **old** original P2 `patch_deny.py` is **ART_FAIL** (illegal `fill-array-data-payload` spans an existing try boundary); do not reuse it for a real APK. The replacement `host_candidate/patch_deny_art_safe.py` removes the pseudo-payload entirely, using existing original DEX strings and ordinary NOPs, preserving the pre-existing code headers/try table. Static gate: https://github.com/u2584604327-a11y/dshe/actions/runs/40818265220

### New independently pinned DEX sequence

- ART-safe native deny P1 DEX SHA256: `8565675b7da207e858f1c3dd69896ce5a68015a24605157a4a11b259218119b6`
- Browser getter patch P2 SHA256: `e392e65bf7592ddd9531af81459e678d1462423abed526d5eeddac248ab158a4`
- WebView settings patch P3 SHA256: `8682204473860802b17b18ab487fa72380eb076d37495d2de4abb76abad0df6b`
- Native P8 `bundlePath` suppression SHA256: `086d0e431515d9f5072109e96a94cbbe7f37c578f1cc68722bcd787881d1acb3`
- P5 D8 extension SHA256: `552d593f42596a624b36374243f48aec10ffec6a9006eaa1b4974bc84ffab56b`

### Genuine disposable Android ART and launch

Full P1–P8 fusion, test-sign/install, offline ART compilation and app launch: **PASS** at https://github.com/u2584604327-a11y/dshe/actions/runs/40818441206

- SHA256 of ephemeral unsigned pre-alignment fusion: `6c492f80df83f77dfc34f9deb64ad0825a5f490e6cf8c72ddd80a7fea87887f7`.
- 965 untouched APK file entries verified byte-for-byte, P5 63 compiled classes inserted as `classes3.dex`.
- GitHub runner generated a new ephemeral self-signed keystore, **not** the original production certificate. Test APK and keystore were deleted after emulator testing, never published.
- On a clean Android 35 emulator, APK install was **PASS**; offline `cmd package compile -m speed -f com.dsh.android` was **PASS**.
- Explicit MainActivity launch succeeded, DSH process remained alive across the observation window; prior `VerifyError` was not detected. `DISPOSABLE_ANDROID_EMULATOR_LAUNCH=PASS`.
- This proves a **limited startup ART gate**, not every P5 class or feature. No user data from a real device was present.
- P5 new classes were compiled and packaged but original Activity is still **not wired** to `NativeDiagnosticReview`; no trusted native one-shot send has been enabled.
- The P7/P8 path redaction does **not** create a separate Node UID or block generic same-UID reads. This remains a hard security blocker.

### Current trustworthy gates

```text
EXACT_V138_INPUT_SHA=PASS
OLD_P2_ART=FAIL_DO_NOT_SHIP
NEW_ART_SAFE_DENY_STATIC=PASS
NEW_P1_TO_P8_FUSED_APK_STRUCTURE=PASS
DISPOSABLE_ANDROID35_OFFLINE_ART_COMPILE=PASS
DISPOSABLE_ANDROID35_MAINACTIVITY_LAUNCH=PASS
P5_NEW_CLASSES_EXECUTED=NOT_VERIFIED
TRUSTED_NATIVE_REVIEW_WIRED=NO
ALL_NODE_AND_NATIVE_DIAGNOSTIC_EGRESS_CLOSED=NOT_VERIFIED
APP_BROWSER_DEVICE_SETTINGS_UI_WIRED=NO
WEBVIEW_STORAGE_ISOLATION=NOT_VERIFIED
PRODUCTION_V139_VERSIONCODE_GREATER_THAN_138=NO
SIGNED_WITH_ORIGINAL_FIXED_CERTIFICATE=NO
USER_PHONE_UPDATE_AND_DATA_RETENTION=NOT_TESTED
```

**Important:** No full DSH v139 release has been built or authorized. Do not share the throwaway emulator-signed APK as an installation candidate; do not ask the user to uninstall their installed v138.

## P9 native legacy export fail-closed — Android emulator PASS (2026-10-29)

- Independently verified SHA-pinned static P9 native patch: https://github.com/u2584604327-a11y/dshe/actions/runs/40819381448
- Full P1–P9 ephemeral unsigned fusion + temporary nonproduction signature + fresh offline Android 35 emulator test **SUCCESS**: https://github.com/u2584604327-a11y/dshe/actions/runs/40819495503
- Candidate primary `classes.dex` SHA256: `db1d61fdae52f55b569cc92bc82afbc82c31f305295ef4a2fd3a431177038d29`
- P9 changes exactly **8 bytes** in `LogCommandBridge.doExport`, replacing the original `DiagnosticBundle.build$default` call and move-result with `const/4 v3,#0` and NOPs. The following existing `if-eqz v3` error path is preserved; no new raw diagnostic archive should be created through this old export path. **Runtime export button behavior has not been UI-tested.**
- Other **52,010** method code bodies remain byte identical relative to P8.
- All 965 other original APK entries remain byte-identical in final fusion, P5 D8's 63 class definitions remain separately bundled in `classes3.dex`, and the P6/P7 assets remain pinned.
- Offline ART package compilation = **PASS**, emulator APK install = **PASS**, explicit `MainActivity` launch and process survival = **PASS**; no known startup VerifyError.
- No fixed signer, no release, no user's real app data touched. Temporary APK and temporary keystore were removed by the Runner, versionCode still **138**.
- **Functional tradeoff:** the old full diagnostic ZIP export has been intentionally disabled while native trusted per-bundle approval is unavailable. Existing logs/ZIPs are not deleted. Ordinary file/image send method bodies were not modified by P9.
- **Remaining same-UID risk:** Node can still read pre-existing diagnostic files and may ask for raw `logs.read`/`logs.crashes` content; P9 does not introduce OS process/UID isolation or comprehensively gate generic Node tools.
- **Release hard blockers:** No trusted host UI hook to P5 `NativeDiagnosticReview`; `ApprovedDiagnosticSendGate` still has no bound transport; no full native/Node diagnostic egress enforcement; no Android WebView storage profile separation; no real-phone data-preserving update; no original-certificate versionCode>138 APK.

```text
P9_STATIC_DEFAULT_DENY_RAW_ZIP=PASS
P9_ANDROID35_EMULATOR_INSTALL=PASS
P9_ANDROID35_OFFLINE_ART_COMPILE=PASS
P9_ANDROID35_MAINACTIVITY_LAUNCH=PASS
P9_DIAGNOSTIC_EXPORT_BUTTON_RUNTIME_TEST=NOT_RUN
P5_TRUSTED_REVIEW_WIRED=NO
GENERIC_NODE_SAME_UID_EXFILTRATION_BLOCKED=NO
PRODUCTION_V139_APK=NOT_BUILT
USER_PHONE_V138=UNCHANGED
```

Do NOT publish or sign the ephemeral candidate. Avoid asserting total privacy gate closure based only on P9 disablement.

## P10 all original external direct ZIP builder calls denied — emulator PASS (2026-10-29)

Verified by four independent pieces of private Actions evidence:

1. Original direct native bundle constructor reachability audit: https://github.com/u2584604327-a11y/dshe/actions/runs/40819987540
2. Exact return/branch context analysis for `LogViewerActivity.exportBundle$lambda$41` and `LogUploader.collectCrashScenes`: https://github.com/u2584604327-a11y/dshe/actions/runs/40820114161
3. P10 exact v138 → ART-safe P1 → browser/privacy → P8/P9 → P10 direct callsite and method scope regression: https://github.com/u2584604327-a11y/dshe/actions/runs/40820289771 (**SUCCESS**)
4. P1–P10 temporary unsigned APK + ephemeral throwaway signer + fresh offline Android 35 simulator: https://github.com/u2584604327-a11y/dshe/actions/runs/40820408827 (**SUCCESS**)

### Native changes and proof boundary

- Original `DiagnosticBundle.build$default` direct DEX callers were identified in `LogCommandBridge.doExport`, `LogViewerActivity.exportBundle$lambda$41`, `LogViewerActivity.upload$lambda$49` and `LogUploader.collectCrashScenes`. Three more calls were within `DiagnosticBundle`'s own implementation. These are a **static inventory of direct calls**, not reflection/JNI/Node reachability.
- The first two existing sends had already been denied by ART-safe P1, P9. P10 now replaces two more external builder callsites, **8 bytes each** (existing register set to null + NOP), with the original failure/result branches preserved.
- `ALL_DIRECT_EXTERNAL_DIAGNOSTIC_BUILD_DEFAULT_CALLS=ZERO_STATIC` in the candidate original primary DEX.
- Full P10 candidate primary DEX SHA256: `cfe19482edcd4bea7c1b476bb90da5b956759c98a2bb101ee9dd459be4a15474`.
- P5 native additional DEX remains 63 class definitions. P6/P7 resources retain their pinned preimages.
- Both original ZIP-building methods (`LogViewerActivity` manual export, uploader crash scene collection) are deliberately **unavailable** pending native trusted review. Local log browsing, summary, and ordinary attachment send instruction bodies were not rewritten by these patches. Runtime manual export UX remains untested.
- Android 35 fresh emulator install: **PASS**; offline ART package compile: **PASS**; explicit MainActivity launch and process survival: **PASS**. This is a limited launch check, not native P5 dialog or full feature validation.
- All generated APKs were **temporary emulator-signed**, versionCode remains **138**, and were deleted from Runner after use. No original signing key used, no GitHub APK release created, and user's existing phone v138 is unchanged.

### Release blockers and mandatory next work

- `P5_TrustedNativeReview` still **not invoked** from `LogViewerActivity` lifecycle / user gesture, and `ApprovedDiagnosticSendGate` transport is intentionally unbound. Actual one-package native preview and one-shot dispatch are **not implemented in original host**.
- Existing ZIPs and raw logs remain readable by Node with the same UID; Node generic shell/file/network tooling has not been isolated. Blocking ZIP creation through original known DEX direct callers is **not** a comprehensive Node exfiltration prevention layer.
- No full Android/Kotlin Gradle host project is present in this repository; binary-level DEX patches alone do not provide a safe way to wire new P5 Activity methods or guarantee all network sinks.
- Browser device settings UI is not hooked to the original activity; same-app WebView cookie/storage profile separation remains unverified.
- No original-certificate signed `versionCode > 138` release, no data-preserving user phone update, and no ART proof of every P5 class under UI flows.

```text
P10_ALL_ORIGINAL_DIRECT_EXTERNAL_ZIP_BUILD_CALLS=ZERO_STATIC
P10_EXACT_DEX_AND_METHOD_SCOPE=PASS
P10_ANDROID35_INSTALL=PASS
P10_ANDROID35_ART_COMPILE=PASS
P10_ANDROID35_MAINACTIVITY_LAUNCH=PASS
P10_NATIVE_MANUAL_EXPORT_USER_FLOW=NOT_VERIFIED
P5_NATIVE_CONSENT_UI_WIRED=NO
P5_EXCLUSIVE_APPROVED_SEND_TRANSPORT_WIRED=NO
GENERIC_NODE_UID_FILE_EXFILTRATION_CLOSED=NO
REAL_PHONE_DATA_PRESERVATION=NOT_TESTED
FIXED_CERT_SIGNED_V139_APK=NOT_BUILT
```

**Do not ship the test-signed APK or expose a v139 installation link.** It does not include the production signer or complete host and egress integration.

## P11 summary-only Node tool + P5 Android UI runtime gate (2026-10-29)

### P11: source + Node execution PASS, production still unchanged

- P11 private GitHub Actions: https://github.com/u2584604327-a11y/dshe/actions/runs/40822332733 — **SUCCESS**.
- Source: `host_candidate/patch_logs_metadata_only.py`, using exact SHA-pinned original v138 `assets/logs-tool.zip` plus P7 export-output redaction.
- New P11 ZIP SHA256: `29bcf54bb00ea989516b8bc7bdeb6bbd68f9a11a85082273399eb3597cdd76a0`.
- The AI `logs` plugin now denies `read`, `crashes` and `export` before dispatching any mailbox command, regardless of attempted arguments. `summary` projects only bounded integer counters and fixed explanatory strings; it discards native arbitrary `message`, `headline`, `lastExit`, `logText`, `sceneText`, `bundlePath` and nested `details`. Synthetic canary leak test PASS.
- The native log viewer, on-disk data, existing ZIP files and other Node/shell generic file tools are **not** protected by this specific plugin-only restriction. The Node process still shares application UID; **total native/Node diagnostic egress closed = NO**.
- P11 resource has been added to the ephemeral P1–P10 assembler, with exact pinned hash. This is **not an installed user update**.

### P5 actual Android UI smoke: newly discovered runtime boundary

- Same-ephemeral-signer Android instrumentation source: `host_candidate/test-only/com/dsh/p1/smoketest/DshInstrumentation.java`; the instrumentation package is never shipped or published.
- Original disposable Android 35 App and instrumentation APK build/installation worked in https://github.com/u2584604327-a11y/dshe/actions/runs/40821972738, but `NativeDiagnosticReview` UI was **not displayed**: the P5 `AndroidFdQueue` constructor raised `IOException`. Thus previous P5 Java compile and package success must **not** be called native UI runtime PASS.
- A subsequent bounded diagnostic https://github.com/u2584604327-a11y/dshe/actions/runs/40822506334 showed `FAIL_PHASE=NATIVE_PINNED_QUEUE`, `FAIL_REASON=SYNTHETIC_QUEUE_PERMISSIONS`. Its strict mode requirement rejects group/other-writable roots. Do **not** loosen the ownership/permissions checks.
- The instrumentation fixture now creates an explicitly native-owned mode `0700` private queue root under a disposable subdirectory; no app-shared filesDir mode is changed and no old logs are removed. The retest is https://github.com/u2584604327-a11y/dshe/actions/runs/40822933877, and remains **NOT_VERIFIED** until its actual result.
- This P5 UI test is intentionally invoked by a test harness from MainActivity, **not** by the original LogViewerActivity button. Even success cannot establish host UI wiring or one-shot transport integration.

```text
P11_NODE_LOG_MODEL_BOUNDARY=PASS_SYNTHETIC_REAL_PLUGIN
P11_FULL_APP_EGRESS=NOT_VERIFIED
P5_NATIVE_UI_ANDROID=NOT_VERIFIED_PENDING_0700_QUEUE_RETEST
P5_ORIGINAL_LOGVIEWER_HOOK=NO
P5_ONE_SHOT_SEND_CONNECTED=NO
ORIGINAL_CERT_V139_APK=NO
PHONE_V138_UNCHANGED=YES
```
