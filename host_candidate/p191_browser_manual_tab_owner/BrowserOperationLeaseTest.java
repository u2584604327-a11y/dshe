package com.dsh.android.browser;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

public final class BrowserOperationLeaseTest {
  static int checks;
  static void ok(boolean value,String name) {
    checks++; if (!value) throw new AssertionError("P189_" + name);
  }
  public static void main(String[] args) throws Exception {
    BrowserOperationLease f = new BrowserOperationLease();
    long a = f.begin();
    ok(a>0,"initial_lease");
    ok(f.isCurrent(a),"owner_live");
    ok(f.begin()==0L,"second_owner_rejected_before_first_finishes");
    ok(!f.complete(a+1),"wrong_lease_cannot_complete");
    ok(f.cancel(a),"timeout_cancels");
    ok(f.mayCleanupCancelled(a),"timeout_cleanup_before_next");
    long b=f.begin();
    ok(b>a,"new_epoch");
    ok(!f.mayCleanupCancelled(a),"stale_timeout_cannot_cleanup_new");
    ok(!f.complete(a),"old_callback_cannot_complete");
    ok(f.complete(b),"new_callback_can_complete");
    ok(!f.complete(b),"duplicate_callback_denied");
    long c=f.begin();
    ok(f.enterManual(),"manual_enter_user_action");
    ok(f.isManual(),"manual_state_visible");
    ok(!f.isCurrent(c),"manual_revokes_active");
    ok(!f.complete(c),"late_callback_manual_denied");
    ok(!f.cancel(c),"late_timeout_manual_denied");
    ok(f.begin()==0L,"new_ai_commands_denied_manual");
    ok(!f.enterManual(),"duplicate_manual_begin_denied");
    ok(f.leaveManual(),"user_manually_ends");
    ok(!f.leaveManual(),"duplicate_manual_end_denied");
    long d=f.begin();
    ok(d>c,"old_lease_not_reused_after_manual");
    ok(!f.complete(c),"old_callback_after_manual_end_denied");
    ok(f.complete(d),"fresh_command_allowed_after_user_end");
    // A delayed cancellation cleanup is safe only until the next epoch.
    long e=f.begin();
    ok(f.cancel(e),"cancel_2");
    ok(f.mayCleanupCancelled(e),"cleanup_2");
    long g=f.begin();
    ok(!f.mayCleanupCancelled(e),"stale_cleanup_2_denied");
    ok(f.complete(g),"current_after_cancel_allowed");
    // Race: all stale callbacks and 2nd-owner claims lose to a newer epoch.
    BrowserOperationLease concurrent = new BrowserOperationLease();
    long stale = concurrent.begin();
    concurrent.cancel(stale);
    long current = concurrent.begin();
    AtomicInteger falseAccepts = new AtomicInteger();
    CountDownLatch start = new CountDownLatch(1),done=new CountDownLatch(16);
    for(int i=0;i<16;i++)new Thread(()->{
      try { start.await(); if(concurrent.complete(stale) ||
          concurrent.mayCleanupCancelled(stale)) falseAccepts.incrementAndGet(); }
      catch(InterruptedException interrupted){ Thread.currentThread().interrupt(); }
      finally { done.countDown(); }
    }).start();
    start.countDown();done.await();
    ok(falseAccepts.get()==0,"concurrent_old_callbacks_all_denied");
    ok(concurrent.complete(current),"current_survives_concurrent_stale");
    System.out.println("P189_BROWSER_OPERATION_EPOCH_AND_MANUAL_TAKEOVER=PASS checks="+checks);
  }
}
