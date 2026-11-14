# P191 — Original BrowserBridge callback tab identity and manual fullscreen integration

Source baseline: `pht88888888/DSHAPP@4dddb12fd076d052e788a16638a658b7a447b669` (MIT). Target changes repo only `u2584604327-a11y/dshe`, existing Draft PR #80 and branch `dsh/p96-original-engine-stream-owner-narrow-20261030`.

Replaces the previous uncommitted P190/P189 candidate. **Do not stack those patchers.**

## What changed over P190

1. `AiBrowserView` now exposes `activeTabRevision()` backed by an atomic monotonically incrementing value. All `showActiveTab()` tab rebindings, closing the last tab (both close entrypoints), and `destroy()` invalidate that value. A tab switch away and back remains detectably different.
2. Original `BrowserBridge.mainThreadOp` captures the tab revision before calling a browser tool. Upon callback it declines to return success if the revision changed, while still restoring browser touch control under the active operation's lease. It never reports the new tab's URL as success for the old tab.
3. Explicit `tabs new`, `tabs close`, and `tabs select` use the narrowly named `allowTabChange` option, as those instructions intentionally move the active tab; ordinary navigation/read/click/type/screenshot/wait do not receive that exception.
4. P190 user-controlled manual challenge fullscreen, same WebView/cookies and no automatic challenge action, remains unchanged. Exit fullscreen does not end manual takeover.

## Actual evidence

- GitHub connector original upstream SHA and blobs: `AiBrowserView.kt=82a025f3190f89968e76dfb62ea9c12f629cc7c7`, `BrowserBridge.kt=ab6e1cdf0073e212906d4f4af4e1855238941120`. DSH PR #80 SHA last confirmed `c3d08081fb1cc9e7deb6257c4d3ed8c51ad9be8c`.
- All source edit anchors verified exactly once against the GitHub-observed original snippets. Full original app compilation remains unexecuted until a GitHub Actions CI run.
- `bash run_local.sh` runs 29 Java 8 lease checks, 22 patched Kotlin mainThreadOp lifecycle checks (including stale async result, away-and-back, intentional model tab mutation), 19 P190 extracted fullscreen Kotlin checks, plus patch-anchor negative tests and compile checks: 70 local dynamic assertions plus static checks.
- All stub tests run WITHOUT Android. No real WebView, real user login challenge or original production engine test is claimed. Actual user P51 ARM64 Node test remains PASS from prior user log, without a repeat device action.

## Build/CI and permission boundaries

Copy P191 package source files (except docs) to `host_candidate/p191_browser_manual_tab_owner/` on existing branch; workflow to `.github/workflows/p191-original-browser-manual-tab-owner.yml`. Checkout pinned upstream inside disposable CI, patch exactly two Kotlin files plus new pure Java `BrowserOperationLease.java`, compile `:app:compileSystemDebugKotlin :app:compileSystemDebugJavaWithJavac`. CI is scoped to the two new paths. No APK, no keystore, no migration, no real user device, no cookie/token extraction, no Cloudflare bypass. Existing P47 host fallback DENY, P109 DENY_ALL, GS screenshot OFF.

**Known limits**: Already-started JS cannot be undone. User navigation on the same unchanged tab has no per-navigation epoch and may still overlap a pending callback. Model `tabs` commands are intentional switch exemptions; a concurrent user tab switch during their asynchronous completion is extremely narrow in existing synchronous source but not a proof for arbitrary future behavior. Formal v139 remains STRUCTURAL_BLOCKED pending EngineManager three launch paths, Binder, production resource broker, genuine Node HTTP token READY.
