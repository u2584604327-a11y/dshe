# Q Mobile v0.1.4 — QQ bot with lighter context

Independent, unofficial mobile adaptation of Tencent Connect's unchanged
`@tencent-connect/dsh-qqbot@0.5.5` (MIT). Based on original
[initial2024/q](https://github.com/initial2024/q) Q Mobile v0.1.3.

## Install URL — only after CI publishes the TGZ

```text
https://raw.githubusercontent.com/u2584604327-a11y/dshe/refs/heads/release/q-mobile-0.1.4/dist/dsh-qqbot-q-mobile-0.1.4.tgz
```

Paste into the DSH Android plugin install URL. This is a **DSH TGZ plugin,
not an APK**. It still installs its exact Tencent dependency from npm.

**Version 0.1.4 improvements**
- Newly created QQ plugin profiles have `historyLimit:3` (maximum three
  buffered QQ group background messages, not three private chat turns).
- Idle Agent memory is evicted after 12 minutes by default, but stored DSH
  sessions can resume; this does **not** delete historical conversations.
- Friendly, concise Chinese group/direct prompts encourage natural conversation,
  without pretending to be a human or fabricating prior memories.
- **Choose a model without typing IDs**: in authorized QQ chat, send
  `/model`. Tencent's official 0.5.5 implementation enumerates the live
  DSH models and returns clickable model commands. The settings page's
  provider/model text fields remain as an advanced fallback.
- Use `/compact` to summarize old context when the selected DSH preset has
  compaction service; use `/new` for a fresh active session.

**Important:** the 3-message limit is only for short group-message background,
NOT a hard cap on durable Agent session memory. The official provider and QQ
session/history implementation is intentionally unchanged. We cannot promise
strict memory deletion or a permanently bounded number of private chat turns.

**Existing installations:** upgrade will not overwrite `cordis.patch.yml`,
whitelists, AppID/AppSecret, or previously customized prompts. Apply the above
new-install values explicitly in your existing trusted local profile if desired.
Do not post credentials publicly.

**Access:** new installs keep `c2cMode=allowlist` (empty until permitted),
`groupMode=open` for groups officially authorized by QQ, and
`requireMention=true`. QQ slash commands are subject to official
`access.commandMode`; restrict command use to trusted users in groups.

**Troubleshooting:** Real @ bot + `/bot-ping`, then real @ + `/model`.
Existing installations with `access.groupMode=disabled` must explicitly
enable an authorized group; this update never silently broadens access.

**Rollback:** [Q Mobile v0.1.3 TGZ](https://raw.githubusercontent.com/initial2024/q/main/dist/dsh-qqbot-q-mobile-0.1.3.tgz);
disable only the plugin if Android DSH startup fails. Do not delete your DSH
profile or mobile QQ account.

**Verification:** the GitHub workflow installs exact official dependency,
rebuilds the Tencent-derived client with nonblocking Android DSH slots,
runs Node tests, and publishes a TGZ. Actual DSH Android binding, background
survival, QQ private/group responses, and clickable model presentation
must still be verified on the phone.

This release branch is isolated from the DSH mainline and PR #80.
Official QQ copyright and terms remain © Tencent Connect, MIT.
See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
