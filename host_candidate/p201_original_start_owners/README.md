# P201 — actual signed-v138 EngineManager direct callsites and upstream-event candidate graph

**Problem:** P198 established exactly 4 app-DEX direct callsites to `EngineManager.start`, 1 to `probeBoot` and 3 to `runDumpConfig`. P199 and P200 genuinely ran the unmodified original launcher on Android 35 and did not observe an original coroutine stack-shape transition during their bounded windows. The next step is **which original method symbols actually contain those 8 instructions, and which other original app methods call them**—not another timer extension.

## Implemented static-only audit

- Require exact SHA256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5` for the signed-v138 APK. Iterate all original application `classes*.dex` using pinned androguard 4.1.4. Never read real user data or launch Node.
- Resolve original `invoke-*` target references by fully qualified DEX owner, method and **normalized descriptor** (not guessed source names). Require the same 4/1/3 directly observed target counts as P198; mismatched counts, duplicate method definition, graph beyond preset limits, corrupt ZIP, changed original SHA or unknown decoder fail closed.
- For each of the eight sites, retain its actual DEX symbolic caller method (allowlisted app-namespace identifier), method descriptor **hash only**, bytecode PC and opcode. Walk inbound app method edges at most three levels, tracking multiple exact callers without inventing an interface/reflective edge. Report at most six readable sample symbols per level and a separate bounded count. Other package methods are excluded.
- Categorize caller class name as Activity / Fragment / ViewModel / Service / Controller / Application / View / other; method name `onClick` / `onResume` / `run` / `invokeSuspend` etc can yield *event signature candidates* only. **A static `onClick` symbol is not evidence that a human tapped it or that the callback has run**. If a path is missing or dynamic, classify its trigger as unresolved; do not fabricate a UI interaction.
- Emit no raw invoke argument registers, original string constants, cookies, private paths, IP addresses, tokens, URLs, prompt content, command lines, HTTP frames, original APK or private dumps. Only original package code class/method symbols, hashes, callsite PCs and fixed categories appear in CI output. The JSON report is ephemeral and deleted; it is never an uploaded artifact.

This graph proves *potential DEX call relationships* only. It does not authenticate actual Android lifecycle UI execution, an original `EngineManager$start$2.invokeSuspend` runtime owner generation, P184 framework receipt delivery to the genuine coroutine, original process/reader/latch/StateFlow correspondence or ARM64 Node/FD native dependencies and token-bearing HTTP READY. P47 main/probe/config host fallback **DENY** and P109 native sensitive tools **DENY_ALL** remain unchanged. P192 isolated TCP `BIND_EACCES` is a frozen negative; P102 native user approval is not bypassed.

## Real-phone testing — authorized for a later phase, not performed here

The user authorized **future** real-device testing on Android arm64. This does **not** imply a phone is currently connected to CI/ChatGPT, permission to install this temporary same-package APK, consent to read user files or permission to unlock root/Shizuku/native tools.

A future real-phone test should be deliberately staged:

1. **Preflight:** explicit per-test user consent; record Android version/API and ABI through user-approved device diagnostics; verify exact intended APK SHA256, signing certificate, package ID, declared permissions and whether any pre-existing installation exists. The original v138 and any update must have compatible signing lineage for an in-place upgrade. A CI-generated temporary same-package APK uses an unrelated test key and **must never** be used to replace the installed DSH. Do not uninstall the installed app to circumvent signing mismatches or erase user data.
2. **Safe smoke tests first:** use a separately installable, intentionally isolated test package where supported, with no access to the original DSH sandbox, accounts, mailbox, cookies, photos, or personal files. Check startup, lifecycle, UI control visibility and manual consent on the physical screen. If device connection or a required test build is unavailable, report **NOT_TESTED**, do not guess or ask for remote-control credentials.
3. **Do not grant sensitive capabilities by default:** any Shizuku/root/MediaProjection/accessibility/screenshot/native tool permission requires an explicit, local, human action and a separate justification. Respect phone OEM WebView behavior, account challenges, third-party platform limits and actual site policies.
4. **Upgrade validation last:** only when a compatible original signing certificate and data-preserving upgrade are independently verified on a disposable test profile/backup, and all host/isolated owner/FD/Node safety gates pass. Then verify no loss of sessions/configuration and a working rollback strategy. Do not publish an APK marked final on the basis of Java8 tests or x86_64 emulator results.

Future manual browser privacy QA sites are documented separately in `host_candidate/p198_original_source/BROWSER_PRIVACY_QA.md`; they are not queried by automated CI and never used to bypass platform risk controls.

Retain the actual original DSHAPP/pht88888888 MIT attribution and the independent, nonofficial modification disclaimer. Formal v139 remains `STRUCTURAL_BLOCKED`.
