# P106 Original MIT Android host: reproducible source compile preflight (isolated, no APK)

The pinned public source `pht88888888/DSHAPP@4dddb12fd076d052e788a16638a658b7a447b669` is a **candidate for a compatible native host source development baseline**, not the original signed v138 build itself.

## Verified wiring facts from upstream source

1. `EngineManager.ensureBrowserTool()` unpacks `browser-tool.zip` into `$DSH_HOME/browser-tool/dsh-android-browser`. `writeBrowserToolPatch()` generates `browser-tool.patch.yml` and mounts the plugin at engine startup.
2. The Node `mobile-ui-plugin/dsh-android-browser/lib/index.js` plugin `apply(ctx)` registers `ctx.tools.register(browserTool(home))`; its `execute(args)` uses incrementing *plugin-local* integer `seq` and writes `browser-cmd.json`. That `id` is a mailbox correlation number, **not** the original ToolRuntime `callId` or `SessionStore` live ownership proof.
3. `BrowserBridge.start(home, host)` launches a Kotlin poller. `execCommand()` accepts `open/read/click/type/press/scroll/screenshot/back/forward/reload/tabs/eval/wait` from JSON in the shared DSH home, and writes `browser-result.json`. It has no authoritative native UID+live original-session+pending-tool-call verifier in this path. The original mailbox must therefore NOT be made a privileged approval path.
4. Original `EngineService.onBind(Intent?): IBinder? = null` is a foreground/wakelock service, **not** an already exposed service Binder for trusted tool results. A new isolated service/Binder implementation would require explicit source and manifest changes, with a trusted independent verifier. Reusing `EngineService` without a contract would be wrong.
5. `MainActivity.installBrowserBridge()` only provides a live WebView host; `bootEngine()` invokes `engine.ensureExtracted` and `engine.start`; no proof it independently validates original Node `SessionStore` and `ToolRuntime`.

## Build preflight

`.github/workflows/p106-pinned-upstream-system-kotlin-compile.yml` uses the exact public MIT source commit, JDK17 and Gradle 8.13 to compile **Kotlin system Debug sources** in temporary CI worktree. It must not assemble APK, use release signing, inject a production bridge, install apps or upload any executable. It reports the actual outcome and fails closed if source prerequisites are missing.

If source compile passes, the next narrow branch task is to integrate a *fail-closed, separately reviewed* native broker in a **staged upstream source patch** inside the authorized PR #80, with no origin-app replacement and without exporting any release credential. If source compilation fails, collect exact missing compile deps and fix only the candidate build prerequisites, never use v138's installed data or keys.

## Mandatory release distinction

P104/P105 prove v135-v138 binary continuity and some v91 tool assets are identical. The public Kotlin source versionCode 91 is **not** proved source-equivalent to modified signed v138 versionCode 138. Restore all verified v138 assets (especially browser-tool ZIP) before any compatible build is considered. v139 official `com.dsh.android` release remains blocked until original ToolRuntime ownership, original Node→Android isolated Binder/UID boundary, one native consent/result, original AgentLoop autonomous continuation, all P0/P1 phone regressions and data-preserving same-certificate upgrade are independently established.
