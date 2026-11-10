# Q Mobile v0.1.9 — model switching returns without automatic UI network requests

This is an **unofficial DSH TGZ plugin**, not an APK. The upstream QQ transport,
binding, SDK, authentication and message delivery are still delegated unchanged
to Tencent Connect `@tencent-connect/dsh-qqbot@0.5.5` (MIT).

## Install

```text
https://raw.githubusercontent.com/u2584604327-a11y/dshe/refs/heads/release/q-mobile-0.1.9/dist/dsh-qqbot-q-mobile-0.1.9.tgz
```

Install in DSH Plugin Manager. Keep the original QQ configuration and stored
credentials. Do not run this wrapper alongside the official QQ plugin in the
same profile (the Cordis row id `im-qqbot` must remain unique).

## Model selection in QQ settings

The model selector has been restored in its own **optional React component**;
it does **not** add hooks to the existing Tencent ConfigPanel. It makes **zero
requests during DSH Web boot**.

1. Open Q Mobile → QQ 机器人设置 → 模型与提示词.
2. Tap **读取可用模型** to request current host-registered models.
3. Choose the model. The official Provider/Model draft fields are updated.
4. Tap the existing official **保存** button, which may reload the QQ plugin.

The selection is **the QQ plugin's default route**, not necessarily a
per-person/per-group override. For a specific QQ conversation, the official
`/model` command still lists and switches live models without a global settings
save; the official `/model provider/model` syntax is also preserved.

If the host does not expose `llm.listProviders/listModels`, or the catalog
cannot be reached, the selector shows a failure hint. The existing manual
Provider/Model inputs and QQ `/model` command remain usable.

The model catalog is read-only, host-authenticated, origin-checked, bounded
and uses a short-lived cache. No QQ credential, token or chat history is
provided to the model picker. It does not route model requests itself.

## Why this design

- v0.1.6 had a real Android crash: `ReferenceError: fetchJson is not defined`.
- v0.1.7 removed that error but was not fully phone-verified.
- v0.1.8 restored the known-working official settings renderer by removing
  experimental model UI; that also removed the desired dropdown.
- v0.1.9 keeps the v0.1.8 startup/official settings adapter and adds one
  isolated, on-demand model picker. Failure does not hide manual fields.

## Context and reply safety

- First-install `historyLimit: 3` bounds buffered QQ group background.
  It is **NOT a hard cap** on durable DSH memory or on private chat turns.
- First-install `sessionIdleTimeout: 720000`, `maxQueue: 3`, and
  `requireMention: true` are retained.
- **群聊仅回复 @机器人的消息** where the official platform allows the bot.
- Private chat starts with an empty allowlist until an authorized user is added.
- Existing configurations are not overwritten by upgrading.
- The tone prompt is natural and concise without impersonation or fabricated
  personal memory. Commands `/compact` and `/new` stay official.
- There is no guarantee of exactly-once outbound QQ message delivery;
  ambiguous send timeouts must not be blindly retried.

## Acceptance and rollback

Automated CI tests validate the package and synthetic settings cases.
Actual Android DSH rendering and QQ private/group delivery require a
phone check. Verify DSH settings open, the selector loads or degrades,
choosing and saving a model, `/model` in QQ, and a multi-turn private chat.

If the Android interface fails, disable only this plugin rather than
clearing all app data. Roll back to the tested stable UI package:

https://raw.githubusercontent.com/u2584604327-a11y/dshe/refs/heads/release/q-mobile-0.1.8/dist/dsh-qqbot-q-mobile-0.1.8.tgz

This branch is isolated from DSH mainline and its PR #80.
Tencent MIT attribution and licenses remain in the package.
