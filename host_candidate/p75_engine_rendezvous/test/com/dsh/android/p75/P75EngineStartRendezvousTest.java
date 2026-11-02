package com.dsh.android.p75;
import com.dsh.p37.P37RemoteProcess;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
public final class P75EngineStartRendezvousTest {
  static final String S="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  static final P37RemoteProcess.IsolatedUidVerifier UID = u->u==99055;
  static int count;
  static void check(boolean yes,String why){count++;if(!yes)throw new AssertionError("P75_"+why);}
  static P37RemoteProcess remoteFor(String session,int uid){
    return new P37RemoteProcess(uid,session,u->u==uid,new P37RemoteProcess.RemoteControl(){
      public void requestGracefulStop(){}
      public void requestForceStop(){}
    });
  }
  static P37RemoteProcess remote(){return remoteFor(S,99055);}
  static ProcessBuilder fixture(){return new ProcessBuilder("/system/bin/id","-u").directory(new File("/"));}
  static String error(ProcessBuilder p){
    try{P75EngineStartRendezvous.startOrDeny(p);return "UNEXPECTED_SUCCESS";}
    catch(IOException e){return e.getMessage();}
  }
  public static void main(String[] args)throws Exception{
    check(error(fixture()).equals("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK"),
          "unarmed_denied");
    P75EngineStartRendezvous.armFromTrustedHost(S);
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99055,UID),
          "child_before_engine_call_denied");
    AtomicReference<Process> result=new AtomicReference<>();
    AtomicReference<Throwable> err=new AtomicReference<>();
    Thread engine=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(S);
        result.set(P75EngineStartRendezvous.startOrDeny(fixture()));
      }catch(Throwable e){err.set(e);}
    },"p75-original-engine-worker-simulated");
    engine.start();
    check(P75EngineStartRendezvous.awaitOriginalBridgeEntered(2000),"wait_entered");
    check(error(fixture()).equals("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK"),
          "other_thread_not_authorized");
    // P168 negative: the host session/UID in the callback can be correct
    // while the remote Process proxy belongs to a different session/UID.
    // Before the P168 fix these two forged-proxy calls were accepted.
    check(!P75EngineStartRendezvous.authenticatedChildStarted(
          S,remoteFor(S.replace('a','b'),99055),99055,UID),
          "other_session_proxy_denied_even_when_callback_session_matches");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(
          S,remoteFor(S,99056),99055,UID),
          "other_uid_proxy_denied_even_when_callback_uid_isolated");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99056,UID),
          "wrong_framework_uid");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S+"bad",remote(),99055,UID),
          "wrong_session");
    P37RemoteProcess verified=remote();
    check(P75EngineStartRendezvous.authenticatedChildStarted(S,verified,99055,UID),
          "authenticated_child_accepted");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99055,UID),
          "duplicate_child_denied");
    engine.join(2500);
    check(!engine.isAlive()&&err.get()==null,"engine_unblocked_without_exception");
    check(result.get()==verified,"real_identical_proxy_across_threads");
    check(!P75EngineStartRendezvous.isArmed(),"consumed");
    check(error(fixture()).equals("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK"),
          "replay_denied");
    P75EngineStartRendezvous.armFromTrustedHost(S);
    AtomicReference<String> failure=new AtomicReference<>();
    Thread denied=new Thread(()->{
      try{P75EngineStartRendezvous.claimOnEngineThread(S);
          failure.set(error(new ProcessBuilder("sh","-c","unsafe").directory(new File("/"))));}
      catch(Exception e){failure.set("unexpected");}
    });
    denied.start();denied.join(2500);
    check("P75_PRODUCTION_ARGV_NOT_AUTHORIZED".equals(failure.get()),
          "unaudited_argv_never_spawned");
    check(!P75EngineStartRendezvous.isArmed(),"bad_argv_consumes_session");
    P75EngineStartRendezvous.armFromTrustedHost(S);
    AtomicReference<String> cancelled=new AtomicReference<>();
    Thread blocked=new Thread(()->{
      try{P75EngineStartRendezvous.claimOnEngineThread(S);cancelled.set(error(fixture()));}
      catch(Exception e){cancelled.set("unexpected");}
    });
    blocked.start();
    check(P75EngineStartRendezvous.awaitOriginalBridgeEntered(2000),"cancel_wait_entered");
    P75EngineStartRendezvous.cancelSession("BINDER_LOST");
    blocked.join(2500);
    check("P75_CHILD_ACK_MISSING_OR_TIMEOUT".equals(cancelled.get()),
          "binder_loss_returns_error");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99055,UID),
          "late_child_after_cancel_denied");
    check(!P75EngineStartRendezvous.isArmed(),"cancel_cleanup");
    // A real Process may exit after CHILD_STARTED but before the waiting
    // original-engine thread resumes. It is still the correct Process object.
    P75EngineStartRendezvous.armFromTrustedHost(S);
    AtomicReference<Process> shortResult=new AtomicReference<>();
    AtomicReference<Throwable> shortError=new AtomicReference<>();
    Thread quick=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(S);
        shortResult.set(P75EngineStartRendezvous.startOrDeny(fixture()));
      }catch(Throwable e){shortError.set(e);}
    });
    quick.start();
    check(P75EngineStartRendezvous.awaitOriginalBridgeEntered(2000),
          "early_exit_wait_entered");
    P37RemoteProcess shortLived=remote();
    check(P75EngineStartRendezvous.authenticatedChildStarted(S,shortLived,99055,UID),
          "early_exit_child_authenticated");
    check(shortLived.onAuthenticatedExit(99055,S,0),"early_exit_auth");
    quick.join(2500);
    check(!quick.isAlive() && shortError.get()==null &&
          shortResult.get()==shortLived,"early_exit_keeps_actual_process_facade");
    // P170: deterministically prove a cancelled lease's thread capability
    // cannot become valid again if a buggy host reuses an identical session.
    // The old session value alone was previously enough to pass validation.
    P75EngineStartRendezvous.armFromTrustedHost(S);
    CountDownLatch oldClaimReady=new CountDownLatch(1);
    CountDownLatch useOldClaim=new CountDownLatch(1);
    AtomicReference<String> staleResult=new AtomicReference<>();
    Thread staleClaim=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(S);
        oldClaimReady.countDown();
        if(!useOldClaim.await(3,TimeUnit.SECONDS)){
          staleResult.set("THREAD_COORDINATION_TIMEOUT");
          return;
        }
        staleResult.set(error(fixture()));
      }catch(Exception exception){staleResult.set("THREAD_EXCEPTION");}
    },"p170-cancelled-generation-engine-thread");
    staleClaim.start();
    check(oldClaimReady.await(2,TimeUnit.SECONDS),"old_generation_claimed");
    P75EngineStartRendezvous.cancelSession("CANCELLED");
    P75EngineStartRendezvous.armFromTrustedHost(S);
    useOldClaim.countDown();
    staleClaim.join(2500);
    check(!staleClaim.isAlive(),"old_generation_rejected_without_waiting");
    check("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK".equals(staleResult.get()),
          "cancelled_generation_cannot_reuse_identical_session_string");
    check(P75EngineStartRendezvous.isArmed(),"fresh_generation_not_consumed_by_stale_thread");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99055,UID),
          "fresh_generation_child_not_accepted_without_fresh_bridge_call");
    P75EngineStartRendezvous.cancelSession("CANCELLED");
    check(!P75EngineStartRendezvous.isArmed(),"fresh_generation_can_be_cancelled");
    System.out.println("P170_CANCELLED_LEASE_REARM_SAME_SESSION_STALE_THREAD_DENIED=PASS");
    System.out.println("P75_CROSS_THREAD_ENGINE_BINDER_RENDEZVOUS_JVM=PASS assertions="+count);
    System.out.println("P75_NON_MAIN_LAUNCH_WAITS_FOR_AUTHENTICATED_CHILD=PASS");
    System.out.println("P75_UNAUTHORIZED_ARGV_AND_NO_HOST_FALLBACK=PASS");
    System.out.println("P75_REAL_PRODUCTION_NODE_AND_READY=NOT_TESTED");
  }
}
