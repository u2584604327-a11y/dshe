# P203 — original v138 MainActivity.bootEngine parent upstream call sites

P201 proved all 4 direct EngineManager.start caller lambdas in the exact signed original DEX. P202 resolved each real Kotlin lambda constructor parent and PC:
- BOOT: `MainActivity.bootEngine`, constructor call PC26.
- AUTO_SAFE: `MainActivity.autoEnterSafeMode`, PC104.
- MANUAL_SAFE: `MainActivity.enterSafeMode`, PC104.
- OBSERVE: `MainActivity$observeEngine$1$1.emit`, PC1432.

**P203 targets their real upstream method calls**, prioritizing bootEngine, rather than rechecking P150 synthetic stack counters or adding a timer to P199/P200.

The scanner requires the *signed original* v138 APK SHA256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`. Pinned androguard decodes original `classes*.dex`; a caller is accepted only when the exact original parent class+method contains a direct constructor `invoke-direct` targeting the exact P202 suspend class at the exact P202 PC. The tool also checks the frozen original 4+1+3 direct EngineManager.start/probeBoot/runDumpConfig callsite counts, and the unique `invokeSuspend` method in each of the four classes. Unexpected source hash, overload, compiler reordering, missing/duplicate original anchor, instruction mismatch and graph size overflow **fail closed**.

For each original anchored parent method, collect exact typed inbound app `invoke-*` edges using owner/name/descriptor, follow at most 4 levels of original app methods, and print at most 10 original code method symbols/PCs along with counts, class roles and *possible* method signature categories. A method named `onClick`, `onCreate`, `invokeSuspend`, `emit`, `access$...` etc can only provide a **signature hint**, not an actual Android callback, user gesture, original runtime call or OS credential. Missing inbound direct edges are explicitly counted as zero; reflection, Kotlin scheduling, Flow and virtual dispatch are **NOT_EXHAUSTIVELY_RESOLVED**. A method name alone cannot authorize Node or a native tool.

The fixture is static and read-only, not a user-facing test build. It never invokes original `EngineManager.start()`, changes `MainActivity`, bypasses P47, starts original Node, opens a browser, or uses any site/IP/account. It does not collect raw invoke operands, original code strings, private paths, device data, cookies, auth tokens, original binary or other user files. Ephemeral reports and signed original APK scratch are erased at the end, never uploaded.

**Acceptance scope**: 22 negative synthetic unit tests, real signed-APK 4+1+3 and four PC/callee anchor verification, actual bounded original caller graph and a GitHub job conclusion. PASS means the graph was decoded, not that a UI event happened. No original Kotlin coroutine platform attestation or P184 one-use receipt to the genuine original Process/reader/latch/StateFlow is proven. ARM64 original FD/JS/native and bearer HTTP READY remain blocked.

**True-device verification, later only**: User permits a later, deliberate Android arm64 device test. The P201 safety protocol remains binding: inspect device API/ABI, intended APK SHA/signing certificate/package/permissions with explicit user consent, install a separate side-by-side test app first, never overwrite or uninstall existing DSH with the disposable different-signer CI APK, do not read user data or grant root/Shizuku/MediaProjection/native tools without an additional local user action. There is no phone connection or real-device install in P203.

P192 isolated UID direct TCP denied remains negative evidence and must not be bypassed. P109 sensitive native tools DENY_ALL and GS capture OFF. BrowserLeaks, Abraham Juliot original CreepJS GitHub Pages, IPhey, BrowserScan, EFF and AmIUnique remain manual opt-in browser diagnostics only, not automated CI requests or fingerprint spoofing. Retain DSHAPP/pht88888888 MIT credit and bilingual unofficial modification disclosures. Formal v139 = `STRUCTURAL_BLOCKED`.
