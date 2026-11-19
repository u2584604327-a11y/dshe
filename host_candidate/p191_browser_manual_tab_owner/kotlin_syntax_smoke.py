#!/usr/bin/env python3
"""Compile the *exact AST-defined replacement function* with Kotlin JVM stubs.
Android full original is still a distinct real-CI gate.
"""
import ast
from pathlib import Path
ROOT = Path(__file__).parent
mod = ast.parse((ROOT/'patch_original_browser.py').read_text())
body = next(v for v in mod.body if isinstance(v, ast.FunctionDef) and v.name=='patch_bridge')
method = None
for node in ast.walk(body):
    if isinstance(node, ast.Assign) and any(isinstance(t,ast.Name) and t.id=='new' for t in node.targets) and isinstance(node.value,ast.Constant):
        if 'private fun mainThreadOp(' in node.value.value: method = node.value.value
assert method is not None
stub='''package com.dsh.android.browser
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
class JSONObject(val message:String="OK")
class AiBrowserView {
  @Volatile var aiControl:Boolean = false
  @Volatile var tabRevision:Long = 0L
  fun activeTabRevision():Long=tabRevision
  fun simulateTabSwitch(){tabRevision++}
  var silentInput:Boolean = false
  fun claimAiControl(){aiControl=true}
  fun releaseAiControl(){aiControl=false}
  fun hideActionSoon(){}
  fun hideActionNow(){}
  fun showAction(s:String){}
}
interface BrowserHost {
  fun browserOrNull():AiBrowserView?
  fun onToolActivity(s:String){}
  fun onToolDone(){}
}
class Handler {
  fun post(a:()->Unit):Boolean { a();return true }
  fun postDelayed(a:()->Unit, delay:Long):Boolean {return true}
}
class BrowserBridgeStub {
  private val browserLease = BrowserOperationLease()
  private val mainHandler=Handler()
  private val OP_TIMEOUT_MS=500L
  private var currentPill="test"
  private var provider:(()->BrowserHost?)?=null
  private var lastView:AiBrowserView?=null
  fun err(msg:String):JSONObject = JSONObject("ERR:"+msg)
  fun setHost(host:BrowserHost){provider={host}}
  fun runOp(op:(AiBrowserView,(JSONObject)->Unit)->Unit):JSONObject=mainThreadOp(op=op)
  fun runTabMutation(op:(AiBrowserView,(JSONObject)->Unit)->Unit):JSONObject=mainThreadOp(allowTabChange=true,op=op)
  fun manualBegin():Boolean=browserLease.enterManual()
  fun manualEnd():Boolean=browserLease.leaveManual()
''' + method + '\n}\n'
(ROOT/'P189BridgeKotlinCompileStub.kt').write_text(stub)
(ROOT/'P189CookieStub.kt').write_text('''package android.webkit
class CookieManager {
  fun flush(){}
  companion object {
    fun getInstance():CookieManager=CookieManager()
  }
}
''')
print('P189_EXACT_PATCH_METHOD_EXTRACTED_KOTLIN_JVM_FIXTURE=YES')
