package com.dsh.android.browser
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

fun main() {
  val bridge=BrowserBridgeStub()
  val view=AiBrowserView()
  bridge.setHost(object: BrowserHost {
    override fun browserOrNull():AiBrowserView = view
  })
  val oldEntered=CountDownLatch(1)
  val oldCallback=AtomicReference<((JSONObject)->Unit)>()
  val oldResult=AtomicReference<JSONObject>()
  val first=Thread {oldResult.set(bridge.runOp{_,cb->oldCallback.set(cb);oldEntered.countDown()})}
  first.start()
  check(oldEntered.await(1,TimeUnit.SECONDS))
  first.join(1200)
  check(!first.isAlive)
  check(oldResult.get().message.startsWith("ERR:"))
  val freshEntered=CountDownLatch(1)
  val freshCallback=AtomicReference<((JSONObject)->Unit)>()
  val freshResult=AtomicReference<JSONObject>()
  val second=Thread {freshResult.set(bridge.runOp{_,cb->freshCallback.set(cb);freshEntered.countDown()})}
  second.start()
  check(freshEntered.await(1,TimeUnit.SECONDS))
  check(view.aiControl)
  oldCallback.get().invoke(JSONObject("OLD_SUCCESS"))
  check(view.aiControl) // old callback never releases newer operation
  freshCallback.get().invoke(JSONObject("NEW_SUCCESS"))
  second.join(1000)
  check(freshResult.get().message=="NEW_SUCCESS")
  check(!view.aiControl)
  val inFlight=CountDownLatch(1)
  val pendingCb=AtomicReference<((JSONObject)->Unit)>()
  val third=Thread {bridge.runOp{_,cb->pendingCb.set(cb);inFlight.countDown()}}
  third.start()
  check(inFlight.await(1,TimeUnit.SECONDS))
  check(bridge.manualBegin())
  val denied=bridge.runOp{_,_->throw AssertionError("manual cannot invoke op")}
  check(denied.message.contains("人工操作"))
  pendingCb.get().invoke(JSONObject("LATE_SUCCESS"))
  third.join(1000)
  check(bridge.manualEnd())
  val resumed=bridge.runOp{_,cb->cb(JSONObject("USER_APPROVED_NEW_OP"))}
  check(resumed.message=="USER_APPROVED_NEW_OP")
  // A stale asynchronous page callback may not report a new active tab URL.
  val tabInFlight=CountDownLatch(1)
  val tabCallback=AtomicReference<((JSONObject)->Unit)>()
  val tabResult=AtomicReference<JSONObject>()
  val tabThread=Thread { tabResult.set(bridge.runOp { _,cb ->
    tabCallback.set(cb); tabInFlight.countDown()
  }) }
  tabThread.start()
  check(tabInFlight.await(1,TimeUnit.SECONDS))
  view.simulateTabSwitch()
  tabCallback.get().invoke(JSONObject("WRONG_TAB_SUCCESS"))
  tabThread.join(1200)
  check(!tabThread.isAlive)
  check(tabResult.get().message.contains("标签页已切换"))
  check(!view.aiControl)

  // Explicit model commands to new/select/close tabs must still work.
  val changed=bridge.runTabMutation{v, cb ->
    v.simulateTabSwitch()
    cb(JSONObject("INTENTIONAL_TAB_CHANGE_SUCCESS"))
  }
  check(changed.message=="INTENTIONAL_TAB_CHANGE_SUCCESS")
  check(!view.aiControl)

  // Switching away and back leaves a different monotonic revision.
  val away=CountDownLatch(1)
  val awayCb=AtomicReference<((JSONObject)->Unit)>()
  val awayResult=AtomicReference<JSONObject>()
  val awayThread=Thread {awayResult.set(bridge.runOp{_,cb->
    awayCb.set(cb);away.countDown()
  })}
  awayThread.start()
  check(away.await(1,TimeUnit.SECONDS))
  view.simulateTabSwitch()
  view.simulateTabSwitch()
  awayCb.get().invoke(JSONObject("SAME_TAB_BUT_OLD_CALLBACK"))
  awayThread.join(1200)
  check(!awayThread.isAlive)
  check(awayResult.get().message.contains("标签页已切换"))

  println("P191_PATCHED_KOTLIN_TAB_REVISION_AND_LIFECYCLE=PASS checks=22")
}
