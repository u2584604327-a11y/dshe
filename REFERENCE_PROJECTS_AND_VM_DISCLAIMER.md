# DSH v139 — reference projects, virtual-device capability boundary and non-endorsement notice

> Status: design/attribution ledger, 2026-11-04. This is NOT a VM deliverable, security certification, feature availability promise or v139 release approval.

## 1. What is original, what is referenced

| Project / official source | Relationship to this DSH workspace | Verified implementation / rights boundary |
| --- | --- | --- |
| [pht88888888/DSHAPP](https://github.com/pht88888888/DSHAPP), [pinned upstream source](https://github.com/pht88888888/DSHAPP/tree/4dddb12fd076d052e788a16638a658b7a447b669) | Original DSH Android comparison/derivative baseline | Upstream Android MIT notice preserved at `THIRD_PARTY_LICENSES/DSHAPP-MIT.txt`. Pinned public v91 source is **not proven binary-identical to modified signed v138**. Bundled engine/Termux/browser dependencies need separate review. |
| [Shelter, PeterCxy](https://github.com/PeterCxy/Shelter) | **Concept only**: Android Work Profile and separation of per-profile app/account data | Original project GPL-3.0; **no Shelter source or binaries copied** into DSH by this reference. Copying later requires separate compatible-license review. Work Profile is an Android-managed profile, not a complete emulated phone or new physical device. |
| [gVisor, Google](https://gvisor.dev/docs/) | **Concept only**: least privilege, brokered capabilities, limits and independent execution boundary | No `runsc`, application kernel or gVisor source incorporated. A generic Android app/isolatedProcess is **not gVisor** and is **not** a container runtime or hypervisor. Confirm source version and its license if any later reuse is proposed. |
| [AOSP Android `isolatedProcess` and Binder](https://developer.android.com/reference/android/app/Service) | **Android platform API behavior** examined for P15/P43/P68/P192/P193, rather than imported source | Android35 same-package `isolatedProcess` + authenticated Messenger/FD tests are narrow. P192 real isolated UID direct TCP bind returns `BIND_EACCES`; do not grant permissions or turn off isolation to manufacture PASS. |
| [Android WebView data directory suffix](https://developer.android.com/reference/android/webkit/WebView#setDataDirectorySuffix(java.lang.String)) | **API guidance only** for future multiple-process browser store separation | Must be configured before WebView initialization, unique per process; this is not per-tab isolation and does not create a fresh Android user or spoof hardware. **Not wired to production original DSH.** |
| [Android AVF/pKVM and Microdroid](https://source.android.com/docs/core/virtualization) | **Future feasibility research only** for stronger genuine guest isolation | No AVF boot, VM image, hypervisor, guest kernel, privileged API or VM attestation is implemented here. Microdroid runs a restricted Android payload environment, **not** a generic full Android phone GUI. Restricted `MANAGE_VIRTUAL_MACHINE` APIs cannot be assumed available to a regular third-party APK. |
| [OmniGate (separate user project)](https://github.com/initial2024/text) | **Behavioral comparison only**: user-initiated login, session owner lifecycle, explicit account selection, private guest context and human challenge takeover | No GeckoView migration or OmniGate code/import is established in current DSH PR. OmniGate's independently tested APK or browser sign-in does not validate DSH v139. Reuse of its code would need exact source/ownership/license and source-range record. |

**Reference is not incorporation.** This ledger names inspirations and upstream behavior. It does not mean the authors contributed code to this DSH patch, approved the changes, or endorsed the project. For future third-party code reuse, record upstream repository, exact revision, files/assets copied, SPDX identifier and applicable full notices, hash, compatibility decision, modified files and whether shipped in a release. Do not label a concept-only reference as a shipped dependency.

## 2. Device simulation — planned versus actually proven

| Tier | Claimed capability | Evidence/status as of 2026-11-04 |
| --- | --- | --- |
| L1 browser presentation | Viewport, DPR, UA, locale, touch layout presets | P16 source fixture available. Actual network/JS/CH/WebGL/TLS/IP identity consistency for real websites **not verified**; default is native Android WebView. |
| L2 isolated browser account storage | Process-scoped distinct CookieManager, site storage and cache, normal/temporary sessions | **Not production implemented**, and not proven multi-account E2E. Different tabs or UA values alone are not isolation. |
| L3 sandboxed execution | Separate isolated UID; authenticated bounded Binder/FD grants | Some real Android35 tests exist (P43/P44/P68), **but original production Node/EngineManager broker not wired**. P192 TCP bind denied in isolated UID. |
| L4 virtual device management | Independently lifecycle-managed data profiles, permission revoke and optional snapshot/rollback | **Planned**, no production sandbox manager, VM snapshot or independently isolated browser filesystem. |
| L5 independent Android guest | Hypervisor/guest kernel/virtual hardware/OS services | **NOT IMPLEMENTED**. P44 sends a synthetic `sandbox-a` configuration (`390x844`, `en-US`, `UTC`, network denied, broker-only storage) to an authenticated isolated worker and checks its SHA-256. That is a profile handshake, not Android VM boot. |

Read the primary bounded evidence in `host_candidate/P44_VIRTUAL_DEVICE_SCOPE_AND_TRUST_GATE.md`, `host_candidate/P14_P16_SECURITY_AND_DEVICE_MODE_STATUS.md`, `host_candidate/p191_browser_manual_tab_owner/P191_README.md` and [P192 real negative](https://github.com/u2584604327-a11y/dshe/pull/80#issuecomment-6631004466). Do not describe mocked, x86_64-emulated or compiler-only checks as original ARM64 production proof.

## 3. Anti-abuse, account integrity and compatibility safeguards

- Default to the actual device's stable native WebView/UA, normal coherent platform signals and explicit user-controlled account sessions. Do not use cross-device UA/fingerprint/hardware/GPU/TLS/attestation impersonation as an anti-bot strategy.
- Separate profiles for **privacy and data boundaries**, not for evading service limits or anti-fraud restrictions. A Work Profile, WebView directory, isolated UID or guest context cannot promise unique real hardware identity, unique public IP, or immunity from fingerprint correlation.
- A CAPTCHA, Turnstile, suspicious-login challenge or identity check may only be completed by the user in the website's legitimate browser interaction. No automated challenge clicks, token capture/replay, security-check bypass, or challenge-result forgery.
- 429/403, verification required, account restriction, risk notice or uncertain request outcome must pause the relevant provider/account. No automatic account, IP, proxy or device-profile rotation to circumvent provider restrictions; no silent duplicate send. User explicitly chooses further permitted action after the site allows it.
- Account picker and browser switching must not background-open unrelated provider sessions. User takeover stops AI browser operations, cancels stale leases, and preserves the same page and cookies without changing UA mid-challenge. No unsolicited comments, DMs, form submits or other external side effects.
- Sensitive file/device/native tools are denied by default, scoped to explicit user approval, revocable and audited without raw tokens. `P47` host ProcessBuilder fallback DENY, `P109` native sensitive tools DENY_ALL and GS capture OFF remain unchanged.
- Source compile or synthetic negative-test PASS is **not** evidence that a website will accept the environment. Platform anti-bot decisions cannot be guaranteed or engineered away.

## 4. Current release gate and required architecture

Main blocker remains P193: host UID may own the **127.0.0.1-only** listener; the isolated worker cannot be assumed to open any network socket. The sole allowed model is a narrowly scoped, authenticated Binder/Messenger frame bridge with framework UID verification, owner/session/epoch/nonce binding, exact once/replay rejection, bounded data/time/queue budgets, and fail-closed cancellation. Even successful fixture tests will not establish genuine ARM64 Node execution, full original JS/FD runtime or token-bearing HTTP READY.

Formal fixed-signature v139 APK: **STRUCTURAL_BLOCKED / NOT RELEASED**. No production device install, data migration, original-user account access, license grant, signing credential or official endorsement is asserted by this file.

## 5. Disclaimer / 免责声明

**中文**：本工程为独立的非官方二次修改与安全研究/验证工程，不代表 DSHAPP 原作者、DeepSeek、Shelter、gVisor、Google/AOSP 或 OmniGate 的官方认可。所有已验证能力仅限所列测试范围；部分功能为设计或模拟。不得保证网站免风控、设备指纹真实性、账号不被限制、数据绝对安全或可无损覆盖安装。原作者对本工程修改不承担责任；任何对外发布必须逐项核验许可、权利、第三方通知、签名与用户数据安全。

**English**: This is an independent, unofficial modification and verification workspace, not endorsed by the original DSHAPP author, DeepSeek, Shelter, gVisor, Google/AOSP or OmniGate. References do not imply shipped code. Experimental, synthetic and emulated tests are not guarantees of a real VM, site acceptance, fingerprint identity, anti-abuse exemption, account safety or production readiness. Original third-party authors are not responsible for independent modifications. Before redistribution, review every copied component's license, notices, signing, provenance and user-data safety. Provided **AS IS**, without warranties.
