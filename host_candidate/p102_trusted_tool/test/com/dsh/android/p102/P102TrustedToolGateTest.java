package com.dsh.android.p102;

import com.dsh.android.p71.P71ToolReplyOnce;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/** Deterministic JVM8 security tests. Does NOT claim real Android Binder. */
public final class P102TrustedToolGateTest {
  static int checks;
  static void check(boolean b,String tag){
    checks++;
    if(!b)throw new AssertionError("P102_"+tag);
  }
  static final class Clock implements P102TrustedToolGate.MonotonicClock {
    long time=1000;
    public long elapsedRealtimeMs(){return time;}
  }
  static final String SESSION="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  static final int UID=99055;
  static final class Lab {
    final Clock clock=new Clock();
    final AtomicInteger executions=new AtomicInteger();
    final List<P71ToolReplyOnce.Terminal> replies=new ArrayList<>();
    final P102TrustedToolGate gate;
    Lab(){
      gate=new P102TrustedToolGate(UID,SESSION,clock,u->u==UID,
        (name,args)->{
          if(!P102TrustedToolGate.TOOL.equals(name)||
             !P102TrustedToolGate.FIXED_ARGS.equals(args))
            throw new AssertionError("P102_NOT_FIXED_EXECUTION");
          executions.incrementAndGet();return true;
        },r->{synchronized(replies){replies.add(r);}});
    }
    P102TrustedToolGate.Decision request(String call){
      return gate.accept(UID,SESSION,call,P102TrustedToolGate.TOOL,
        P102TrustedToolGate.FIXED_ARGS);
    }
    int replies(){synchronized(replies){return replies.size();}}
    P71ToolReplyOnce.Terminal last(){
      synchronized(replies){return replies.get(replies.size()-1);}
    }
  }
  public static void main(String[] args)throws Exception{
    boolean bad=false;
    try{new P102TrustedToolGate(UID,SESSION,new Clock(),u->false,
        (n,a)->true,r->{});}catch(IllegalArgumentException ex){bad=true;}
    check(bad,"must_be_isolated_uid");
    bad=false;
    try{new P102TrustedToolGate(UID,"caller-chosen-session",new Clock(),u->true,
        (n,a)->true,r->{});}catch(IllegalArgumentException ex){bad=true;}
    check(bad,"must_be_host_minted_session_shape");

    Lab noApproval=new Lab();
    check(noApproval.request("call-1")==P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL,
      "request_pending_native_approval");
    check(noApproval.executions.get()==0,"never_execute_before_approval");
    check(noApproval.replies()==0,"no_premature_terminal_result");
    check(noApproval.request("call-2")==P102TrustedToolGate.Decision.REJECTED,
      "no_second_pending_call");
    check(noApproval.gate.onTrustedNativeApproval("wrong")==
      P102TrustedToolGate.Decision.REJECTED,"wrong_ui_callid_denied");
    check(noApproval.executions.get()==0,"wrong_ui_did_not_execute");
    check(noApproval.gate.onTrustedNativeApproval("call-1")==
      P102TrustedToolGate.Decision.DISPATCHED,"native_approval_dispatches_once");
    check(noApproval.executions.get()==1,"exactly_one_execution");
    check(noApproval.replies()==1&&noApproval.last().ok,"one_successful_terminal");
    check(noApproval.last().dispatched&&!noApproval.last().retrySafe,
      "success_is_not_retryable");
    check(noApproval.gate.onTrustedNativeApproval("call-1")==
      P102TrustedToolGate.Decision.REJECTED,"approval_replay_denied");
    check(noApproval.replies()==1,"no_second_result");

    Lab wrongUid=new Lab();
    check(wrongUid.gate.accept(UID+1,SESSION,"caller",P102TrustedToolGate.TOOL,
      P102TrustedToolGate.FIXED_ARGS)==P102TrustedToolGate.Decision.REJECTED,
      "spoofed_uid_denied");
    check(wrongUid.gate.isTerminal(),"spoofed_uid_revokes_binding");
    check(wrongUid.executions.get()==0,"spoofed_uid_no_effect");

    Lab wrongSession=new Lab();
    check(wrongSession.gate.accept(UID,SESSION.substring(0,63)+"0","caller",
      P102TrustedToolGate.TOOL,P102TrustedToolGate.FIXED_ARGS)==
      P102TrustedToolGate.Decision.REJECTED,"wrong_session_denied");
    check(wrongSession.executions.get()==0,"wrong_session_no_effect");

    Lab unknownTool=new Lab();
    check(unknownTool.gate.accept(UID,SESSION,"call","write_file",
      P102TrustedToolGate.FIXED_ARGS)==P102TrustedToolGate.Decision.REJECTED,
      "arbitrary_tool_not_allowed");
    check(unknownTool.request("again")==P102TrustedToolGate.Decision.REJECTED,
      "invalid_tool_burns_attempt");
    Lab badArgs=new Lab();
    check(badArgs.gate.accept(UID,SESSION,"call",P102TrustedToolGate.TOOL,
      "{\"query\":\"/data/user/0\"}")==P102TrustedToolGate.Decision.REJECTED,
      "noncanonical_args_denied");
    check(badArgs.executions.get()==0,"noncanonical_args_no_execute");

    Lab timeout=new Lab();
    check(timeout.request("timeout")==P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL,
      "timeout_queued");
    timeout.clock.time+=P102TrustedToolGate.APPROVAL_WINDOW_MS+1;
    check(timeout.gate.onTrustedNativeApproval("timeout")==P102TrustedToolGate.Decision.EXPIRED,
      "expired_approval_denied");
    check(timeout.executions.get()==0,"timeout_no_execute");
    check(timeout.replies()==1&&!timeout.last().ok&&!timeout.last().outcomeUnknown&&
      timeout.last().retrySafe,"queued_timeout_result_safe");

    Lab lost=new Lab();
    check(lost.request("disconnect")==P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL,
      "disconnect_queued");
    lost.gate.revoke();
    check(lost.replies()==1&&!lost.last().ok&&!lost.last().outcomeUnknown,
      "disconnect_before_dispatch_is_terminal");
    check(lost.gate.onTrustedNativeApproval("disconnect")==P102TrustedToolGate.Decision.REJECTED,
      "disconnect_late_approval_denied");

    Lab failure=new Lab(){
      // Intentional fixture failure is covered below with a direct gate.
    };
    final List<P71ToolReplyOnce.Terminal> failedReplies=new ArrayList<>();
    P102TrustedToolGate rejectedExecutor=new P102TrustedToolGate(
      UID,SESSION,new Clock(),u->u==UID,(name,arguments)->false,failedReplies::add);
    check(rejectedExecutor.accept(UID,SESSION,"fail",P102TrustedToolGate.TOOL,
      P102TrustedToolGate.FIXED_ARGS)==P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL,
      "failed_executor_queued");
    check(rejectedExecutor.onTrustedNativeApproval("fail")==
      P102TrustedToolGate.Decision.DISPATCHED,"failed_executor_dispatched_once");
    check(failedReplies.size()==1&&!failedReplies.get(0).ok&&
      "EXECUTOR_REJECTED".equals(failedReplies.get(0).code),
      "failed_executor_receipt_one");

    Lab concurrent=new Lab();
    check(concurrent.request("race")==P102TrustedToolGate.Decision.PENDING_NATIVE_APPROVAL,
      "race_queued");
    CountDownLatch start=new CountDownLatch(1);
    Thread t1=new Thread(()->{try{start.await();concurrent.gate.onTrustedNativeApproval("race");}
      catch(InterruptedException e){Thread.currentThread().interrupt();}});
    Thread t2=new Thread(()->{try{start.await();concurrent.gate.onTrustedNativeApproval("race");}
      catch(InterruptedException e){Thread.currentThread().interrupt();}});
    t1.start();t2.start();start.countDown();t1.join();t2.join();
    check(concurrent.executions.get()==1&&concurrent.replies()==1,
      "concurrent_native_approvals_one_execution_one_receipt");

    System.out.println("P102_JVM8_NATIVE_TOOL_TRUST_GATE=PASS checks="+checks);
    System.out.println("P102_PREAPPROVAL_DENY_AND_REPLAY=PASS");
    System.out.println("P102_UID_SESSION_CANONICAL_TOOL_AND_TIMEOUT=PASS");
    System.out.println("P102_ONE_TERMINAL_AND_CONCURRENT_NO_DUPLICATE=PASS");
    System.out.println("P102_PRODUCTION_DSH_TOOL_BINDER_WIRED=NO");
    System.out.println("P102_ANDROID_PHONE_E2E=NOT_TESTED");
  }
}
