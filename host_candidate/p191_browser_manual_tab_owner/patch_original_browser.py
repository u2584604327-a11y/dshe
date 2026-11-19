#!/usr/bin/env python3
"""P191 exact SHA-pinned original MIT browser integration, only disposable checkout.

Strictly modifies two original Kotlin sources and adds a pure Java 8 lease.
It never edits an installed app or attempts any site challenge automation.
"""
import argparse
import pathlib
import subprocess

ORIGINAL = "4dddb12fd076d052e788a16638a658b7a447b669"
BRIDGE = "app/src/main/java/com/dsh/android/browser/BrowserBridge.kt"
VIEW = "app/src/main/java/com/dsh/android/browser/AiBrowserView.kt"
FENCE = "app/src/main/java/com/dsh/android/browser/BrowserOperationLease.java"
BRIDGE_BLOB = "ab6e1cdf0073e212906d4f4af4e1855238941120"
VIEW_BLOB = "82a025f3190f89968e76dfb62ea9c12f629cc7c7"


def require(ok, message):
    if not ok:
        raise RuntimeError("P191_DENY_" + message)


def output(*args):
    return subprocess.check_output(list(args), text=True).strip()


def once(data, old, new, name):
    require(data.count(old) == 1, name + "_ANCHOR_DRIFT")
    return data.replace(old, new, 1)


def patch_bridge(src):
    src = once(src,
        "import java.util.concurrent.atomic.AtomicBoolean\n",
        "import java.util.concurrent.atomic.AtomicBoolean\n"
        "import java.util.concurrent.atomic.AtomicReference\n",
        "BRIDGE_IMPORT")
    src = once(src,
        "    private var lastView: AiBrowserView? = null\n",
        """    private var lastView: AiBrowserView? = null

    // P190: one owner per native browser command; no stale timeout cleanup.
    private val browserLease = BrowserOperationLease()

    /** Explicit user interaction only. Does not solve or infer site verification. */
    fun beginManualTakeover(): Boolean {
        if (!browserLease.enterManual()) return false
        mainHandler.post {
            // No WebView replacement, cookie manipulation or automatic replay.
            if (browserLease.isManual()) {
                runCatching {
                    lastView?.releaseAiControl()
                    lastView?.hideActionNow()
                }
            }
        }
        return true
    }

    fun endManualTakeover(): Boolean = browserLease.leaveManual()
    fun isManualTakeover(): Boolean = browserLease.isManual()
""", "BRIDGE_LEASE_FIELD")
    start_mark = "    private fun mainThreadOp(\n"
    end_mark = "\n    /**\n     * 执行用户给的任意 JS"
    require(src.count(start_mark) == 1, "MAIN_OP_START")
    require(src.count(end_mark) == 1, "MAIN_OP_END")
    left = src.index(start_mark)
    right = src.index(end_mark, left)
    old = src[left:right]
    # Assert the exact original semantics being replaced. No drift-adapted replace.
    for marker in (
        "val finished = AtomicBoolean(false)",
        "lastView = view", "op(view) { r ->", "view.releaseAiControl()",
        "host.onToolDone()", "CookieManager.getInstance().flush()",
        "lastView?.releaseAiControl()", "latch.await(OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)",
    ):
        require(marker in old, "MAIN_OP_CONTRACT_" + marker[:12].replace(" ", "_"))
    new = """    private fun mainThreadOp(
        touchesKeyboard: Boolean = false,
        allowTabChange: Boolean = false,
        op: (AiBrowserView, (JSONObject) -> Unit) -> Unit,
    ): JSONObject {
        val lease = browserLease.begin()
        if (lease == 0L) return err("浏览器正在人工操作或其他请求执行中；自动化已暂停")
        val pill = currentPill
        val latch = CountDownLatch(1)
        val box = arrayOfNulls<JSONObject>(1)
        val finished = AtomicBoolean(false)
        val opView = AtomicReference<AiBrowserView?>()

        fun finish(v: JSONObject) {
            if (finished.compareAndSet(false, true)) {
                box[0] = v
                latch.countDown()
            }
        }

        val posted = mainHandler.post {
            try {
                // A queued UI task must not create or mutate a browser after
                // timeout/cancellation or an explicit manual takeover.
                if (!browserLease.isCurrent(lease)) {
                    finish(err("浏览器操作已取消或进入人工模式"))
                    return@post
                }
                val host = provider?.invoke()
                val view = host?.browserOrNull()
                if (view == null) {
                    browserLease.cancel(lease)
                    finish(err("浏览器不可用（Activity 可能正在销毁）"))
                    return@post
                }
                opView.set(view)
                if (!browserLease.isCurrent(lease)) {
                    finish(err("浏览器操作已取消或进入人工模式"))
                    return@post
                }
                // Capture the currently mounted tab before invoking this operation.
                // This revision also changes on a switch away and back.
                val tabAtStart = view.activeTabRevision()
                view.claimAiControl()
                lastView = view
                if (touchesKeyboard) view.silentInput = true
                view.showAction(pill)
                host.onToolActivity(pill)
                op(view) { result ->
                    if (browserLease.complete(lease)) {
                        // Only this operation's callback may release its UI.
                        view.releaseAiControl()
                        view.hideActionSoon()
                        host.onToolDone()
                        runCatching { android.webkit.CookieManager.getInstance().flush() }
                        mainHandler.postDelayed(
                            { runCatching { android.webkit.CookieManager.getInstance().flush() } },
                            2500L,
                        )
                        // An async result belongs to the tab it started on.
                        // Only explicit `tabs` mutations may intentionally
                        // change the active tab during their own operation.
                        finish(if (allowTabChange ||
                            view.activeTabRevision() == tabAtStart) result
                            else err("浏览器标签页已切换；旧页面回调已拒绝"))
                    } else {
                        // Old callbacks never clean up a newer operation.
                        finish(err("过期浏览器回调已忽略；不会自动重试"))
                    }
                }
            } catch (failure: Throwable) {
                if (browserLease.cancel(lease)) {
                    opView.get()?.releaseAiControl()
                    opView.get()?.hideActionSoon()
                }
                finish(err("原生异常: ${failure.javaClass.simpleName}"))
            }
        }
        if (!posted) {
            browserLease.cancel(lease)
            finish(err("主线程拒绝执行"))
        }
        val received = latch.await(OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        if (!received || box[0] == null) {
            if (browserLease.cancel(lease)) {
                mainHandler.post {
                    if (browserLease.mayCleanupCancelled(lease)) {
                        opView.get()?.releaseAiControl()
                        opView.get()?.hideActionSoon()
                    }
                }
            }
            return err("等待页面响应超时（${OP_TIMEOUT_MS}ms），本次操作已撤销")
        }
        return box[0]!!
    }
"""
    patched = src[:left] + new + src[right:]
    # The existing `tabs new/close/select` actions synchronously switch tabs.
    # Their results must not be misclassified as stale page reads.
    patched = once(patched,
        '        return mainThreadOp { view, done ->\n            when (sub) {',
        '        return mainThreadOp(allowTabChange =\n            sub == "new" || sub == "close" || sub == "select") { view, done ->\n            when (sub) {',
        'TABS_EXPLICIT_CHANGE')
    return patched



def patch_view(src):
    # P190: retain the exact original WebView; only its FrameLayout grows.
    # P191: prevent prior-tab asynchronous results from claiming new-tab success.
    src = once(src,
        '    private var activeIndex = -1\n',
        '    private var activeIndex = -1\n'
        '    private val tabRevision = java.util.concurrent.atomic.AtomicLong(0L)\n'
        '    /** Changes on every tab rebinding, including away-and-back. */\n'
        '    fun activeTabRevision(): Long = tabRevision.get()\n',
        'VIEW_TAB_REVISION_FIELD')
    src = once(src,
        '    private fun showActiveTab() {\n',
        '    private fun showActiveTab() {\n'
        '        tabRevision.incrementAndGet()\n',
        'VIEW_TAB_CHANGE_REVISION')
    close_single = ('        if (tabs.size <= 1) {\n'
                    '            onClose?.invoke()\n'
                    '            return\n'
                    '        }\n')
    require(src.count(close_single) == 2, 'VIEW_CLOSE_LAST_TAB_ANCHOR_DRIFT')
    src = src.replace(close_single,
        ('        if (tabs.size <= 1) {\n'
         '            tabRevision.incrementAndGet()\n'
         '            onClose?.invoke()\n'
         '            return\n'
         '        }\n'), 2)
    src = once(src,
        "    private var embedded = false\n",
        """    private var embedded = false

    // P190: exactly the SAME WebView stays mounted while the user handles
    // website verification. Never launch a second WebView or load a URL.
    private var manualFullscreen = false
    private var savedManualFrame: FrameLayout.LayoutParams? = null
    private var deferredManualEmbed: IntArray? = null
    private var manualExitButton: TextView? = null

    /** User gesture ONLY; returning false must not change the page. */
    private fun enterManualFullscreen(): Boolean {
        if (!BrowserBridge.isManualTakeover() || manualFullscreen) return false
        val current = layoutParams as? FrameLayout.LayoutParams ?: return false
        val saved = FrameLayout.LayoutParams(current.width, current.height).apply {
            setMargins(current.leftMargin, current.topMargin,
                current.rightMargin, current.bottomMargin)
            gravity = current.gravity
        }
        savedManualFrame = saved
        deferredManualEmbed = null
        manualFullscreen = true
        val fullscreen = FrameLayout.LayoutParams(
            LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT)
        fullscreen.gravity = Gravity.TOP or Gravity.START
        layoutParams = fullscreen
        visibility = View.VISIBLE
        bringToFront()
        val exit = TextView(context).apply {
            text = "退出验证全屏"
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(0xFFFFFFFF.toInt())
            setBackgroundColor(0xE0182436.toInt())
            setPadding(dp(12), dp(6), dp(12), dp(6))
            setOnClickListener { exitManualFullscreen() }
        }
        manualExitButton = exit
        val exitParams = FrameLayout.LayoutParams(
            dp(118), dp(44), Gravity.TOP or Gravity.END)
        exitParams.topMargin = dp(10)
        exitParams.rightMargin = dp(12)
        addView(exit, exitParams)
        return true
    }

    /** Exiting fullscreen NEVER ends manual mode or resumes AI. */
    private fun exitManualFullscreen(): Boolean {
        if (!manualFullscreen) return false
        manualFullscreen = false
        manualExitButton?.let { removeView(it) }
        manualExitButton = null
        val saved = savedManualFrame
        savedManualFrame = null
        val pending = deferredManualEmbed
        deferredManualEmbed = null
        if (saved != null) layoutParams = saved
        if (pending != null) {
            if (pending.size == 4) applyEmbedRect(
                pending[0], pending[1], pending[2], pending[3])
            else clearEmbedRect()
        }
        return true
    }
""", "VIEW_MANUAL_FULLSCREEN_FIELDS")
    src = once(src,
        '            MenuItem("✎", "标注截图") { startAnnotate() },\n'
        '            MenuItem("⌄", "收起浏览器") { onCollapse?.invoke() },',
        '            MenuItem("✎", "标注截图") { startAnnotate() },\n'
        '            // P190: manual website challenge, same WebView, no loadUrl/reload.\n'
        '            MenuItem("♙", if (BrowserBridge.isManualTakeover())\n'
        '                "结束人工操作" else "人工验证 · 全屏") {\n'
        '                if (BrowserBridge.isManualTakeover()) {\n'
        '                    exitManualFullscreen()\n'
        '                    BrowserBridge.endManualTakeover()\n'
        '                } else if (BrowserBridge.beginManualTakeover()) {\n'
        '                    releaseAiControl()\n'
        '                    enterManualFullscreen()\n'
        '                }\n'
        '            },\n'
        '            MenuItem("⌄", "收起浏览器") { onCollapse?.invoke() },',
        "VIEW_MANUAL_MENU")
    src = once(src,
        "    fun applyEmbedRect(left: Int, top: Int, width: Int, height: Int) {\n",
        """    fun applyEmbedRect(left: Int, top: Int, width: Int, height: Int) {
        // The sidebar may keep sending geometry updates during manual mode.
        // Defer, never shrink the human-controlled challenge page.
        if (manualFullscreen) {
            deferredManualEmbed = intArrayOf(left, top, width, height)
            return
        }
""", "VIEW_EMBED_DEFER")
    src = once(src,
        "    fun clearEmbedRect() {\n",
        """    fun clearEmbedRect() {
        if (manualFullscreen) {
            // Empty sentinel means the sidebar deliberately stopped embedding.
            deferredManualEmbed = intArrayOf()
            return
        }
""", "VIEW_CLEAR_DEFER")
    src = once(src,
        "    fun destroy() {\n",
        """    fun destroy() {
        // Any pending async operation on this detached Activity is stale.
        tabRevision.incrementAndGet()
        // Clean only the fullscreen UI, not cookies or the manual review gate.
        // If an Activity dies, automation remains denied until explicit exit.
        exitManualFullscreen()
""", "VIEW_DESTROY_RESTORE")
    return src


def run(directory, source, dry_run):
    directory = directory.resolve(strict=True)
    source = source.resolve(strict=True)
    require((directory / ".git").is_dir(), "ORIGINAL_CHECKOUT_REQUIRED")
    require(output("git", "-C", str(directory), "rev-parse", "HEAD") == ORIGINAL,
            "ORIGINAL_SHA_DRIFT")
    require(output("git", "-C", str(directory), "status", "--porcelain") == "",
            "CHECKOUT_DIRTY")
    require((directory / FENCE).exists() is False, "LEASE_FILE_ALREADY_EXISTS")
    require(output("git", "-C", str(directory), "hash-object", BRIDGE) == BRIDGE_BLOB,
            "BRIDGE_GIT_BLOB_DRIFT")
    require(output("git", "-C", str(directory), "hash-object", VIEW) == VIEW_BLOB,
            "VIEW_GIT_BLOB_DRIFT")
    fence_file = source / "BrowserOperationLease.java"
    require(fence_file.is_file() and not fence_file.is_symlink(), "LEASE_SOURCE_MISSING")
    bridge = (directory / BRIDGE).read_text(encoding="utf-8")
    view = (directory / VIEW).read_text(encoding="utf-8")
    patched_bridge = patch_bridge(bridge)
    patched_view = patch_view(view)
    require(bridge != patched_bridge and view != patched_view, "NO_EFFECT")
    require(patched_bridge.count("browserLease.complete(lease)") == 1, "COMPLETION_COUNT")
    require(patched_bridge.count("view.activeTabRevision()") == 2, "TAB_EPOCH_GUARD_MISSING")
    require('allowTabChange =\n            sub == "new"' in patched_bridge, "TABS_INTENTIONAL_SWITCH_DENIED")
    require(patched_view.count("tabRevision.incrementAndGet()") == 4, "TAB_INVALIDATION_MISSING")
    require("CookieManager.getInstance().removeAllCookies" not in patched_bridge,
            "COOKIE_MUTATION")
    require("--no-sandbox" not in patched_bridge and "setUserAgent" not in patched_bridge,
            "BROWSER_EVASION")
    if dry_run:
        print("P189_PINNED_ORIGINAL_BROWSER_SOURCES_AND_ANCHORS=PASS_NO_WRITES")
        return
    (directory / BRIDGE).write_text(patched_bridge, encoding="utf-8")
    (directory / VIEW).write_text(patched_view, encoding="utf-8")
    (directory / FENCE).write_bytes(fence_file.read_bytes())
    print("P191_ORIGINAL_BROWSER_BRIDGE_OPERATION_FENCE_WIRED=PASS_SOURCE_PATCH")
    print("P189_ORIGINAL_AIBROWSERVIEW_USER_MANUAL_MENU_WIRED=PASS_SOURCE_PATCH")
    print("P191_NO_LOGIN_COOKIE_UA_OR_CAPTCHA_BYPASS=YES")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--original", type=pathlib.Path, required=True)
    ap.add_argument("--source", type=pathlib.Path, default=pathlib.Path(__file__).parent)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    run(args.original, args.source, args.check)
