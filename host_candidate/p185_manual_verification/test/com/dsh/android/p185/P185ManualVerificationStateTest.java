package com.dsh.android.p185;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class P185ManualVerificationStateTest {
  private static int checks;
  private static void check(boolean yes, String why) {
    if (!yes) throw new AssertionError(why);
    checks++;
  }
  public static void main(String[] args) throws Exception {
    P185ManualVerificationState s=new P185ManualVerificationState();
    check(!s.isEnabled(),"default_off");
    check(!s.isTakeover(),"default_no_takeover");
    check(s.canAutomate(),"normal_flow_unchanged");
    check(!s.beginFromUser(),"cannot_enter_without_opt_in");
    s.setEnabled(true);
    check(s.isEnabled(),"opt_in_explicit");
    check(s.beginFromUser(),"user_can_enter");
    check(!s.canAutomate(),"manual_blocks_automation");
    check(!s.beginFromUser(),"reentrant_begin_rejected");
    check(s.isTakeover(),"takeover_kept_until_user_end");
    check(s.endFromUser(),"explicit_user_end");
    check(s.canAutomate(),"user_end_unpauses");
    check(!s.endFromUser(),"replay_end_no_op");
    s.beginFromUser();
    s.setEnabled(false);
    check(!s.isTakeover(),"switch_off_clears_takeover");
    check(!s.isEnabled(),"switch_off");
    check(!s.beginFromUser(),"disabled_after_switch");
    s.setEnabled(true);
    s.beginFromUser();
    s.revoke();
    check(!s.isTakeover(),"revoke_clears_takeover");
    check(!s.isEnabled(),"revoke_clears_opt_in");
    final P185ManualVerificationState race=new P185ManualVerificationState();
    race.setEnabled(true);
    AtomicInteger won=new AtomicInteger();
    CountDownLatch start=new CountDownLatch(1);
    Thread[] threads=new Thread[16];
    for(int i=0;i<threads.length;i++){
      threads[i]=new Thread(()->{
        try {start.await(); if(race.beginFromUser())won.incrementAndGet();}
        catch(InterruptedException ex){Thread.currentThread().interrupt();}
      });
      threads[i].start();
    }
    start.countDown();
    for(Thread t:threads)t.join(2000);
    check(won.get()==1,"concurrent_entry_exactly_one");
    check(!race.canAutomate(),"race_still_pauses");
    System.out.println("P185_OPTIONAL_MANUAL_WEBVIEW_STATE=PASS checks="+checks);
    System.out.println("P185_CLOUDFLARE_LIVE_CHALLENGE=NOT_TESTED");
    System.out.println("P185_PRODUCTION_BROWSER_DISPATCHER=NOT_WIRED");
  }
}