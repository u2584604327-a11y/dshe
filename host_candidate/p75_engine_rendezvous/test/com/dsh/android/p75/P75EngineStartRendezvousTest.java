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
    // P171: a one-shot pending lease must have EXACTLY ONE engine-thread
    // claimant. A second thread with the same host session cannot race the
    // authentic original-engine caller or consume its Process handoff.
    P75EngineStartRendezvous.armFromTrustedHost(S);
    CountDownLatch ownerClaimed=new CountDownLatch(1);
    CountDownLatch ownerGo=new CountDownLatch(1);
    AtomicReference<Process> ownerProcess=new AtomicReference<>();
    AtomicReference<Throwable> ownerError=new AtomicReference<>();
    Thread owner=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(S);
        ownerClaimed.countDown();
        if(!ownerGo.await(3,TimeUnit.SECONDS))
          throw new AssertionError("owner coordination timeout");
        ownerProcess.set(P75EngineStartRendezvous.startOrDeny(fixture()));
      }catch(Throwable e){ownerError.set(e);}
    },"p171-legitimate-engine-lease-owner");
    owner.start();
    check(ownerClaimed.await(2,TimeUnit.SECONDS),"one_engine_claimed");
    CountDownLatch contenderDone=new CountDownLatch(1);
    AtomicReference<String> contenderResult=new AtomicReference<>();
    Thread contender=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(S);
        contenderResult.set("UNEXPECTED_SECOND_THREAD_CLAIM");
      }catch(SecurityException expected){
        contenderResult.set(expected.getMessage());
      }finally{contenderDone.countDown();}
    },"p171-competing-engine-thread");
    contender.start();
    check(contenderDone.await(2,TimeUnit.SECONDS),"contender_finished_before_valid_engine");
    contender.join(2500);
    check("P75_UNAUTHORIZED_ENGINE_THREAD".equals(contenderResult.get()),
          "second_thread_cannot_claim_exact_pending_lease");
    check(!P75EngineStartRendezvous.authenticatedChildStarted(S,remote(),99055,UID),
          "contender_did_not_create_pending_child_wait");
    check(P75EngineStartRendezvous.isArmed(),"legitimate_pending_not_consumed");
    ownerGo.countDown();
    check(P75EngineStartRendezvous.awaitOriginalBridgeEntered(2000),
          "original_engine_still_enters_its_rendezvous");
    P37RemoteProcess legitimate=remote();
    check(P75EngineStartRendezvous.authenticatedChildStarted(S,legitimate,99055,UID),
          "original_engine_owns_authentic_child");
    owner.join(2500);
    check(!owner.isAlive() && ownerError.get()==null &&
          ownerProcess.get()==legitimate,
          "original_engine_receives_exact_child_not_competitor");
    check(!P75EngineStartRendezvous.isArmed(),"race_consumed_once");
    // P175: pin the authenticated-but-undelivered pending state without
    // a timing-sensitive race. Earlier cases validate the real Binder callback;
    // reflection here is restricted to the JVM cancellation-boundary test.
    P75EngineStartRendezvous.armFromTrustedHost(S);
    java.lang.reflect.Field pendingField=
        P75EngineStartRendezvous.class.getDeclaredField("pending");
    pendingField.setAccessible(true);
    Object lease=pendingField.get(null);
    java.lang.reflect.Field proxyField=lease.getClass().getDeclaredField("proxy");
    proxyField.setAccessible(true);
    java.util.concurrent.atomic.AtomicInteger stops=
        new java.util.concurrent.atomic.AtomicInteger();
    P37RemoteProcess undelivered=new P37RemoteProcess(99055,S,UID,
        new P37RemoteProcess.RemoteControl(){
          public void requestGracefulStop(){}
          public void requestForceStop(){stops.incrementAndGet();}
        });
    proxyField.set(lease,undelivered);
    P75EngineStartRendezvous.cancelSession("BINDER_LOST");
    check(stops.get()==1,"cancel_reclaims_undelivered_child");
    P75EngineStartRendezvous.cancelSession("BINDER_LOST");
    check(stops.get()==1,"duplicate_cancel_does_not_repeat_force_stop");
    check(!P75EngineStartRendezvous.isArmed(),"cancelled_lease_consumed");
    System.out.println("P175_CANCEL_UNDELIVERED_AUTHENTICATED_CHILD_REVOKED=PASS");
    System.out.println("P171_ONE_PENDING_LEASE_EXACTLY_ONE_ENGINE_THREAD_CLAIM=PASS");
    System.out.println("P170_CANCELLED_LEASE_REARM_SAME_SESSION_STALE_THREAD_DENIED=PASS");
    System.out.println("P75_CROSS_THREAD_ENGINE_BINDER_RENDEZVOUS_JVM=PASS assertions="+count);
    System.out.println("P75_NON_MAIN_LAUNCH_WAITS_FOR_AUTHENTICATED_CHILD=PASS");
    System.out.println("P75_UNAUTHORIZED_ARGV_AND_NO_HOST_FALLBACK=PASS");
    System.out.println("P75_REAL_PRODUCTION_NODE_AND_READY=NOT_TESTED");
  }
}
