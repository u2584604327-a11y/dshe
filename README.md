# Q Mobile v0.1.8 — Android safe-mode rollback

Unofficial adapter for unchanged Tencent QQ SDK @tencent-connect/dsh-qqbot@0.5.5 (MIT).
This is a DSH installable TGZ, not an Android APK.

## Verified package URL

https://raw.githubusercontent.com/u2584604327-a11y/dshe/refs/heads/release/q-mobile-0.1.8/dist/dsh-qqbot-q-mobile-0.1.8.tgz

Install in DSH Plugin Manager. Preserve DSH profile and credentials. Do not enable
this adapter and the separate official Tencent QQ plugin in the same profile.

## Why restore the stable settings interface?

Android 2026-11-10 logs confirmed that v0.1.6 crashed a frontend slot due
to missing fetchJson. v0.1.7 eliminated that specific error, but a later
session reported a DSH Web connection retry and the user still had issues.
That new log does NOT establish a second JavaScript exception or prove
a Tencent QQ transport failure.

This version restores the previously working v0.1.4 official client settings
adapter without the experimental custom model-picker injection, and avoids
registering the extra runtime model-catalog service. It does not modify
official QQ login, AppID/AppSecret, WebSocket, messages, or command handling.
Existing stored settings are preserved.

## Choosing a model

In authorized QQ chat, issue the official command /model and choose an
offered supported model. The official settings panel retains advanced
Provider and Model manual fields. The experimental dropdown is disabled
until a separately tested Android version proves safe.

## Conversation stability

New profiles retain three buffered group background messages, 12-minute idle
Agent expiry, a queue limit of three, and genuine @mention requirement in
authorized groups. The empty C2C allowlist in new installs must be configured
for private replies. Updates do NOT overwrite existing profile values.
Buffered group history is not the same as durable DSH memory.

Natural concise prompts remain; no pretending to be human or inventing past
conversations. Use /new for a new active session; /compact where supported.

No guarantee of exactly-once QQ sends, replay suppression, or durable memory
deletion. Do not blindly retry messages after an uncertain QQ send timeout.

## Mobile verification

1. Confirm v0.1.8 is the version actually installed and active.
2. Open QQ settings and ensure manual fields and binding panel render.
3. Confirm real private QQ ping, group @ mention, and /model choices.
4. Send five linked conversation turns, then test foreground/background,
   connectivity loss, and duplicate sends.
5. If blank, compare UI JavaScript errors with DSH Web reconnect messages;
   those are different signals, not proof of the same failure.

Rollback URL:
https://raw.githubusercontent.com/u2584604327-a11y/dshe/refs/heads/release/q-mobile-0.1.4/dist/dsh-qqbot-q-mobile-0.1.4.tgz

Do not clear app data merely to recover the panel. The release branch is
isolated from DSH mainline and PR #80; original license and attribution retained.
