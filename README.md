# DSH Android — 非官方二次修改与验证工程

> **软件出处：** [pht88888888/DSHAPP — DSH for Android](https://github.com/pht88888888/DSHAPP)，原 Android 作者 **pht88888888**，MIT 许可。
>
> **二次修改声明：** 本仓库 `u2584604327-a11y/dshe` 是在第三方 DSH Android 基础上进行独立修改、兼容性审计、安全隔离与功能集成实验的工程。**不是原创 DSH Android 的官方仓库，也不代表原作者或 DeepSeek 官方，修改内容不得归责原作者。**
>
> **版权及许可：** [软件出处和二次修改声明（中英双语）](NOTICE.md) · [原作者完整 MIT 许可](THIRD_PARTY_LICENSES/DSHAPP-MIT.txt)。第三方 DSH 引擎、Termux、浏览器内核及其他资产仍须分别核实其许可，不能笼统视为全部 MIT。
>
> **发布状态：** 正式 `v139` APK **尚未发布**；当前主要是审核与候选集成工程，不得把实验 APK 冒充正式 DSH。

## Original software and independent modifications

**Original Android project:** [DSH for Android / DSHAPP](https://github.com/pht88888888/DSHAPP), © 2026 pht88888888; MIT licensed. **This repository is an independent, unofficial modification and verification workspace, not the original publisher's release.** See [NOTICE.md](NOTICE.md) and the [verbatim original MIT license](THIRD_PARTY_LICENSES/DSHAPP-MIT.txt). Other bundled upstream components may have separate license obligations.

## 版本与来源校验

本项目使用已有 APK 作为修改与回归基线，并保持原版功能优先，不从零重写 AgentLoop、SessionStore、WebView 或 Node 引擎。下述结论只对应已核验的确切文件：

| 基线 | 证据及限定 |
| --- | --- |
| 第三方历史版 v70 | 参考历史 APK；其签名证书与修改版 v135/v138 不同 |
| 修改版 v135 | SHA-256 `394adfbe85b81ce46c285b1c531ffa307432d777e17af04fe5418272c5cc2e99` |
| 修改版 v138 | SHA-256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5` |
| 原作者公开源码 v91 | 固定公开版本 [`4dddb12`](https://github.com/pht88888888/DSHAPP/tree/4dddb12fd076d052e788a16638a658b7a447b669)，MIT；**尚未证明与修改版 v138 二进制完全等价或是直接父版本** |

P104 已验证修改版 v135→v138：970 个同名 APK ZIP 项，968 个内容完全一致；仅 `AndroidManifest.xml` 与 `classes.dex` 存在差异；不能把该事实延伸到 v91→v138。P105 证实 **v138 浏览器工具 `package.json` 与 `lib/index.js` 和公开 v91 不同**，重建不得直接覆盖现有兼容资源。P106 证实公开 v91 Kotlin 宿主可编译，但不是正式生产 APK。

## 当前工程与安全边界

- **唯一工作 PR：** [#80](https://github.com/u2584604327-a11y/dshe/pull/80)（Draft，尚未合并）。
- **真实生产阻断：** 原版 `ToolRuntime → 可信 Android 隔离 Binder → 独立会话/调用归属验证 → 原生授权 → 唯一工具结果 → 原版 AgentLoop 自动续接` 尚未在 `com.dsh.android` 生产环境接通。
- **仅用于验证的独立应用：** `com.dsh.p102.trustedtoolprobe`；其独立 Android35/36 和真实手机安全试验不代表原版 DSH 生产通过。
- **不触碰用户数据：** 不要求卸载原版 `com.dsh.android`，不自动删除手机 APK、浏览器登录或聊天记录，不提交证书私钥、API keys、令牌和个人诊断数据。
- **签名限制：** 原第三方版本的证书与修改版证书不同；只有在合法持有匹配签名凭据且真实安装/数据保留门禁通过后，才能讨论原包覆盖升级。切勿把版本号连续当作签名兼容证明。

## 只读审计与构建状态

本仓库保留 v135/v138 的已锁定 APK 哈希及候选补丁/工作流。大型历史 APK 通过受控 GitHub Release 资产和精确 SHA 审核；不将 APK 提交到 Git 历史。P103–P105 只做公开源码、APK 方法声明及资源对照；P106 使用公开 MIT 原作者源码执行 `gradle :app:compileSystemDebugKotlin`，**仅编译 Kotlin，未打包、安装或签名发布 APK**。

任何需要复制或重新分发原作者 MIT 授权源码/二进制的产物，必须保留 [原作者 MIT 版权和许可](THIRD_PARTY_LICENSES/DSHAPP-MIT.txt)。同时单独核实 DSH/DeepSeek、Termux、GeckoView 等资产的再分发条款。仓库自身新增文件的许可不得根据原作者 MIT 许可擅自推定。

## 正式版门禁

最终 v139 仍须证明原版真实会话与调用归属、Android 隔离执行和授权、Node AgentLoop 结果续接、OmniGate 409 归属一致性、WebView 后台及登录保持、流式 UI、诊断上传默认禁止、固定证书签名和真机覆盖安装数据保留。**全部 P0/P1 测试通过前，不合并发布。**
