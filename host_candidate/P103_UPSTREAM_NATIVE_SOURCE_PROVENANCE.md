# P103: Third-party DSH native-source provenance and minimum-change release route

## New primary source (discovered 2026-10-31)

A publicly readable **MIT-licensed** upstream Android project exists:

- Repository: https://github.com/pht88888888/DSHAPP
- **Pinned source revision:** `4dddb12fd076d052e788a16638a658b7a447b669` (do not float to main)
- License: `LICENSE` at the pinned revision; preserve MIT copyright/notice on copying substantial source.
- `app/src/main/java/com/dsh/android/EngineManager.kt` declares `EngineManager`, `ensureBrowserTool()`, `ensureNodePty()`, `start()`.
- `app/src/main/java/com/dsh/android/MainActivity.kt` declares `MainActivity`, `bootEngine()`, `observeEngine()`, `installBrowserBridge()`.
- `app/src/main/java/com/dsh/android/browser/BrowserBridge.kt` declares the **existing** native `BrowserBridge`; `browser-cmd.json` → native WebView → `browser-result.json` is an established original route.
- `app/src/main/AndroidManifest.xml` declares `.MainActivity` and non-exported `.EngineService`.
- `app/build.gradle.kts` has application ID `com.dsh.android`, native build constraints `minSdk=26`, `targetSdk=28`, and **versionCode = 91** at this revision. The user-installed branch is **signed v138**, so exact native source-to-binary equivalence **IS NOT PROVEN**.
- `docs/agents/browser.md` explicitly describes `ensureBrowserTool` installing the existing `browser-tool.zip` with relative ZIP entries and the original node/browser native mailbox route.

Read-only provenance CI at `.github/workflows/p103-upstream-native-source-provenance.yml` pins this public commit and **separately** pins the *existing* original v138 APK SHA-256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`. It compares package/class/method **identifiers only**. It must explicitly report `P103_PUBLIC_SOURCE_EQUALS_INSTALLED_V138_BINARY=NOT_PROVEN`.

## Crucial distinction and intended next production work

**P102 no-original-source dead end is partially removed:** the upstream Android/Kotlin host implementation is available with MIT licensing. However, this is not permission to discard the current v138 application binary, its signing identity, cookies, home directory, agent, sessions or working functionality.

1. The upstream host has a built-in original browser plugin / command-file bridge. Start by determining whether this existing path can safely perform an **original ToolRuntime read-only browser call**, with true native result return, *without modifying the original provider or adding a second AgentLoop*. The existing native mailbox **does not inherently attest** a live original SessionStore session+callId or enforce sensitive-action native approvals.
2. **The architectural P102 production security gate remains**: original current engine generation, exact pending original ToolRuntime `callId`, still-live `SessionStore` owner and isolated UID must be independently bound and reverified by trusted native host at request, approval and completion. Never turn a Node-supplied string, a JSON file, `exec.agent`, or a true boolean into native authorization.
3. Before any source modification/build, validate source-v138 binary differences against actual signed APK and enumerate native source dependencies and reproducible offline inputs. A source revision at versionCode 91 is **not** a rebuild of user-modified versionCode 138. Compile or test a **side-by-side, newly signed, independently named test package** first, with user authorization and no contact with their installed DSH data.
4. The eventual `com.dsh.android` v139 in-place upgrade requires exact installed package/certificate, legitimate same-signer key or Android-supported signing lineage, versionCode >138, source/asset/DEX ABI compatibility, device consent, all real P0/P1 acceptance gates, rollback and data-preservation evidence. Public MIT source does **not** convey the original signing key. Never take or expose third-party private keys.
5. Do not rerun the frozen P100/P101 synthetic model/tool tests merely because source is available. First validate the pinned upstream provenance, then pick the smallest actual native insertion point and verify a complete *real-original ToolRuntime → trusted native → original tools/result → AgentLoop* flow. Keep original browsers, streaming UI and OmniGate owner-409 safeguards.

## Source availability scope

This repository does **not** yet contain the upstream full Gradle project. The source pointers and hashes are provenance evidence, not a compiled Android host or a verified true v138 source snapshot. No original user-private source, downloaded APK, signing keys, accounts, or session data should be placed in this public evidence file.
