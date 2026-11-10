# Q Mobile v0.1.4 · QQ 群聊无回复诊断及恢复说明

## 已确认的代码级根因

先前首次安装模板 `initial2024/q/cordis.patch.yml` 将
`access.groupMode` 设成 `disabled`。
腾讯官方 @tencent-connect/dsh-qqbot@0.5.5 的
`src/gateway/middleware-setup.ts` 明确顺序：

1. `accessPolicy({group:{mode:config.access.groupMode,allow:config.access.groupAllow}})`
2. `historyBuffer`
3. `mentionGate({requireMentionInGroup:config.requireMention})`
4. QQ 官方事件 -> session/agent.followup -> 官方消息回复

所以群里正确 @ 机器人仍被第一层直接拒绝，而私聊走另一条
`c2cMode/c2cAllow` 策略，能使用不证明群聊策略有效。

## 立即修复已经绑定的手机（无需重新扫码）

DSH → 设置 → QQ 机器人 → 服务范围 → 群聊：

- **所有人（open）**：对应 `groupMode=open`。仅机器人已在群内且
  已通过 QQ 开放平台审核授权、并且发送**真正 QQ @** 才回复。
  「群聊仅回复 @机器人的消息」保持开启。
- **白名单（allowlist）**：填实际 **group OpenID**，**不是群号**。
  非列表内群消息被拒绝。名单空时所有群都被拒绝。
- **禁用（disabled）**：全部群消息直接拒绝，任何 @ 都不生效。

点击**保存**，等官方插件重新加载配置。不需要卸载 QQ、解绑机器人、
删除 AppID/AppSecret、修改 Android APK 或清空 DSH 数据。

注意：从 v0.1.2 升级到 v0.1.3 不会强行覆盖现有 profile，
避免将用户特意关闭的群权限私自打开。
v0.1.3 修改的是**之后新安装**的模板默认值。

## 故障分段验证

1. **先验证群入口**：在目标 QQ 群真正选择机器人并 @，随后输入
   `/bot-ping`。不是仅在文本中手打一个 @ 字符，也不是仅点群名片。
2. **Ping 成功但 AI 不回**：进入 DSH 模型测试，检查 QQ peer 模型
   配置以及后端实际错误（超时/无可用模型），不要乱改 QQ SDK。
3. **Ping 无响应**：查看「群聊 → 所有人/白名单」是否已保存，
   `requireMention=true`，确认机器人确实在该群且官方开发者平台
   对该群的事件接收权限有效、当前 DSH 引擎和 QQ 网关在线。
4. **启用调试日志**：仅在确有必要时于 QQ 机器人设置临时开启
   `debug`，查 `Access blocked` 等官方事件，完成后关闭。
   任何日志/截图不得含 AppSecret、access token、用户 OpenID 或二维码票据。
5. **模型回复失败**：验证群聊发出测试命令会有响应后，再发送
   「@机器人 你好」。群聊不使用私聊相同的流式输出模式。

## 隐私与回退

- 此适配器只提供官方 `groupMode` 默认值；不捕获或注入群消息，
  也不绕过 QQ 官方认证/权限、速率限制或人工审核。
- `open` 可能让所有**已授权且机器人已加入的群**触发处理。
  如仅需一个群，优先使用 `allowlist` + 该群 group OpenID。
- Tencent Connect 官方中间件在 @ 门控前可能执行短期历史缓存；
  不要把 `requireMention` 当成“完全不读取其他群消息”保证。
- 若修复后影响原有设置或启动，请禁用 Q Mobile，保留 profile 和
  凭据；退回最后已验收版。不可删除整个 `.dsh`。
- 只有 GitHub Node 测试与包发布通过时，声明 BUILD PASS；
  群事件、真机后台保活、QQ 平台审核属于独立的实测门禁。

## 二次创作归属

官方 SDK + QQ Bot 插件：
https://github.com/tencent-connect/dsh-qqbot
`@tencent-connect/dsh-qqbot@0.5.5`，Tencent Connect，MIT。

此文件和模板调整由 `initial2024/q` 独立完成，严格保留官方
SDK、UI 绑定、鉴权和消息协议不变；不作官方认证或免封号承诺。
