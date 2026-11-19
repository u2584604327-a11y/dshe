#!/usr/bin/env python3
"""P189 patch-function positive/negative anchors; real upstream compiled in CI."""
from patch_original_browser import patch_bridge, patch_view

BRIDGE = '''package com.dsh.android.browser
import java.util.concurrent.atomic.AtomicBoolean
object BrowserBridge {
    private var lastView: AiBrowserView? = null
    private fun opTabs(sub: String): JSONObject {
        return mainThreadOp { view, done ->
            when (sub) {
                "new" -> done(JSONObject())
            }
        }
    }
    private fun mainThreadOp(
        touchesKeyboard: Boolean = false,
        op: (AiBrowserView, (JSONObject) -> Unit) -> Unit,
    ): JSONObject {
        val finished = AtomicBoolean(false)
        lastView = view
        op(view) { r ->
            view.releaseAiControl()
            host.onToolDone()
            CookieManager.getInstance().flush()
            finish(r)
        }
        lastView?.releaseAiControl()
        latch.await(OP_TIMEOUT_MS, TimeUnit.MILLISECONDS)
    }

    /**
     * 执行用户给的任意 JS
     */
}
'''
VIEW = '''class AiBrowserView {
    private var activeIndex = -1
    private fun showActiveTab() {
    }
    fun closeCurrentTab() {
        if (tabs.size <= 1) {
            onClose?.invoke()
            return
        }
    }
    private fun closeTabAt(index: Int) {
        if (tabs.size <= 1) {
            onClose?.invoke()
            return
        }
    }
    private var embedded = false
    private fun showOverflowMenu() {
        val items = listOf(
            MenuItem("✎", "标注截图") { startAnnotate() },
            MenuItem("⌄", "收起浏览器") { onCollapse?.invoke() },
        )
    }
    fun applyEmbedRect(left: Int, top: Int, width: Int, height: Int) {
    }
    fun clearEmbedRect() {
    }
    fun destroy() {
    }
}
'''

def require(condition,name):
    if not condition:raise AssertionError('P190_PATCH_' + name)

patched=patch_bridge(BRIDGE)
require('val lease = browserLease.begin()' in patched, 'LEASE_MISSING')
require('if (lease == 0L)' in patched, 'MANUAL_NOT_DENIED')
require('if (browserLease.complete(lease))' in patched, 'CALLBACK_NOT_GATED')
require('browserLease.mayCleanupCancelled(lease)' in patched, 'TIMEOUT_NOT_GATED')
require('CookieManager.getInstance().flush()' in patched,'COOKIE_FLUSH_LOST')
require('lastView?.releaseAiControl()' in patched,'TAKEOVER_CONTROL_NOT_RETURNED')
require('return err("等待页面响应超时' in patched,'TIMEOUT_RETURN_LOST')
require('Array' not in patched.split('opView = ')[1][:18],'BAD_LOCAL_VIEW')
require('BrowserBridge' in patched,'PATCH_BAD_SCOPE')
require(patched.count('view.activeTabRevision()')==2,'BRIDGE_NO_TAB_REVISION_CHECK')
require('allowTabChange =\n            sub == "new" || sub == "close" || sub == "select"' in patched,
        'EXPLICIT_TABS_MUST_WORK')
require(patch_view(VIEW).count('tabRevision.incrementAndGet()')==4,'TAB_REBIND_CLOSE_DESTROY_REVISION_MISSING')

view=patch_view(VIEW)
require('BrowserBridge.beginManualTakeover()' in view,'NO_MANUAL_ENTRY')
require('BrowserBridge.endManualTakeover()' in view,'NO_USER_EXIT')
require('MenuItem("⌄", "收起浏览器")' in view,'OLD_MENU_REMOVED')
require('enterManualFullscreen()' in view,'NO_MANUAL_FULLSCREEN')
require('exitManualFullscreen()' in view,'NO_FULLSCREEN_ESCAPE')
require('deferredManualEmbed = intArrayOf(left, top, width, height)' in view,'NO_EMBED_DEFER')
require('deferredManualEmbed = intArrayOf()' in view,'NO_CLEAR_DEFER')
require('exitManualFullscreen()\n' in view,'NO_DESTROY_RESTORE')
require('setOnClickListener { exitManualFullscreen() }' in view,'NO_EXIT_ACTION')
require('BrowserBridge.endManualTakeover()' in view,'NO_EXPLICIT_END')
for fn,original,issue in ((patch_bridge,BRIDGE.replace('lastView = view','lastView = other'),'BRIDGE_DRIFT'),
                          (patch_view,VIEW.replace('MenuItem("✎"','MenuItem("X"'),'VIEW_DRIFT')):
    try:fn(original)
    except RuntimeError:pass
    else:raise AssertionError(issue+' accepted')
# P191 fail-closed anchors: never silently apply to changed original tab APIs.
for broken,patch,code in [
    (BRIDGE.replace('            when (sub) {','            when (other) {'),patch_bridge,'BROKEN_TABS_ACTION'),
    (VIEW.replace('    private fun showActiveTab() {','    private fun restoreTab() {'),patch_view,'BROKEN_TAB_REBIND'),
    (VIEW.replace('            onClose?.invoke()','            onClose?.run()',1),patch_view,'BROKEN_LAST_CLOSE'),
]:
    try:patch(broken)
    except RuntimeError:pass
    else:raise AssertionError('P191_' + code + '_ACCEPTED')
print('P191_ORIGINAL_BROWSER_PATCH_AND_TAB_EPOCH_NEGATIVE=PASS')
