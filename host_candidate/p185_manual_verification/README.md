# P185 — optional manual verification in the existing WebView

Scope: **side-by-side P83 browser fixture only**, not the original installed DSH
MainActivity and not a production anti-bot workaround.

User control: local opt-in checkbox is OFF by default (the app remembers only
the boolean preference). After enabling, the user can tap "在当前内置浏览器中人工验证"
to reveal the **same attached WebView**, directly interact with the website,
and tap "结束人工操作 · 返回聊天" when finished. The UI neither reloads the URL,
replaces the WebView, clears cookies, edits the user agent nor injects challenge
scripts. It does not claim a challenge has been passed. No external browser
is opened by default.

P185ManualVerificationState is pure Java 8. Manual takeover changes
canAutomate() to false; the original production browser dispatcher MUST consult
this state (not wired here) to stop its automation. The P83 UI exposes
isAutomationPaused() for a later gated integration. The optional UI is not a
license to automate CAPTCHA clicks, reuse challenge tokens, spoof browsers
or silently resume external actions. Side effects still require independent
trusted user approval.

Same-HEAD P143 compiles the P83 Android fixture and runs 19 pure-JVM
state/replay/concurrency negative checks. A passing build verifies only this
bounded scope, NOT a live Cloudflare Turnstile solve, real original DSH
BrowserBridge, persistent auth/session or original ARM64 Node. All existing
P47 host fallback/P109 native tools remain DENY; GS screenshot remains OFF.
Formal v139 release continues BLOCKED.
