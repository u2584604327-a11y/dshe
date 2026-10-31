# 软件出处与二次修改声明 / Origin and Modification Notice

**本仓库是非官方的 DSH Android 二次修改、兼容性审计及候选集成工程，不是原创 DSH Android 的官方仓库，也不代表原作者或 DeepSeek 官方。**

**This is an independent, unofficial modification, compatibility-audit and integration-candidate workspace for DSH Android. It is not the official DSH Android distribution and is not endorsed by the original author or DeepSeek.**

## 1. 原软件及作者 / Original project and author

- Original Android project: **DSH for Android / DSHAPP**
- Original source repository: https://github.com/pht88888888/DSHAPP
- Original Android author/copyright holder named in upstream MIT license: **pht88888888**
- Verified publicly accessible original source revision for comparative work: `4dddb12fd076d052e788a16638a658b7a447b669`
- Original Android project license: **MIT License**.
- Its **unaltered original MIT copyright and license notice** is retained at [THIRD_PARTY_LICENSES/DSHAPP-MIT.txt](THIRD_PARTY_LICENSES/DSHAPP-MIT.txt).
- Upstream's README acknowledges the DSH (DeepSeek Harness) engine, Termux, and other components as separate upstream dependencies. Their applicable notices and licenses are not replaced by DSHAPP's MIT license.

## 2. 二次修改方与修改范围 / Independent modification status

- Modification/audit workspace: https://github.com/u2584604327-a11y/dshe
- Status: **independently maintained unofficial derivative work / modification and verification workspace**.
- Changes compared with historic Android APKs can include **browser integration and device-mode additions, native compatibility, safety-boundary experiments, diagnostic-upload controls, and attempted tool-runtime/streaming integration**. Descriptions of *planned or tested* changes are not guarantees that all modifications are implemented in any particular APK.
- The project retains and audits **historical APK baselines** rather than claiming an entirely newly written Android application.
- The currently compared modified signed baselines are v135 and v138; SHA-locked APK comparison found 970 common archive entries, of which 968 entries are byte-identical and only `AndroidManifest.xml` and `classes.dex` differ. See P104 verification for the bounded scope.
- Public original source `versionCode=91` and modified APK `versionCode=138` are **not independently proven identical builds or an exact immediate parent-child lineage**. Similar names, methods and source availability alone do not prove binary ancestry.
- The independent `com.dsh.p102.trustedtoolprobe` testing application is a separate synthetic Binder laboratory, **not** the original `com.dsh.android` app or a released v139 upgrade.

## 3. Redistribution and legal boundaries

- The upstream Android MIT copyright and permission notice must remain in any copy or substantial portion of that upstream MIT-licensed software, including when distributing compatible modified source or APKs containing it.
- This document and the upstream MIT notice **do not** assert that all independently included binaries, bundled DSH engine/frontend, runtime distributions, packages, artwork, or third-party assets have the same license. Verify third-party rights and notices **component by component** before any public redistribution.
- This document preserves the original author's attribution but **does not grant a blanket license to every file in this separate workspace**; any license applicable to new modifications must be decided and stated separately.
- Do not copy the original publisher's name, signature or official branding in a way implying that this modified release was published or endorsed by that publisher.
- The original v70 certificate differs from the modified fixed-signature v135/v138 certificate. A matching applicationId is **not** proof of a valid in-place update; real device signing, versionCode and data-preservation requirements remain mandatory.

## 4. 发布与验证状态 / Release status

- **DSH Android v139 production APK is NOT released or accepted.**
- `P102` synthetic Android Binder E2E, `P103–P105` provenance, and `P106` upstream Kotlin compilation successes do **not** prove original production `ToolRuntime → Android Binder → original AgentLoop` integration.
- This repository is not to be represented as the original author's official release, a production-ready Android source replacement, or a completed data-preserving upgrade.
- No signing private keys, passwords, account data, device identifiers, model tokens, or user sessions should be committed here.

---

*Attribution applies to the original upstream's work. Engineering and verification changes in this workspace are separate; the original author is not responsible for independent modifications.*
