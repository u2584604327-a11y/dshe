package com.dsh.android.p68;

import com.dsh.android.p75.P75EngineStartRendezvous;
import com.dsh.p37.P37RemoteProcess;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * P184 Java8 source-level trust/proof negative cases. Synthetic issuer used
 * ONLY because this JVM fixture has no Android Binder. Separate Android
 * Message.sendingUid proof is still needed before a production claim.
 */
public final class P184ChildStartReceiptTest {
  private static final String S="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final int UID=99055;
  private static int count;
  private static void yes(boolean v,String name){
    count++;if(!v)throw new AssertionError("P184_"+name);
  }
  private static P37RemoteProcess remote(String session,int uid){
    return new P37RemoteProcess(uid,session,u->u==uid,
        new P37RemoteProcess.RemoteControl(){
          public void requestGracefulStop(){}
          public void requestForceStop(){}
        });
  }
  private static P37RemoteProcess remote(){return remote(S,UID);}
  private static P184ChildStartReceipt issue(P37RemoteProcess p,long epoch){
    return new P184ChildStartReceipt(p,UID,S,epoch,()->true);
  }
  private static ProcessBuilder fixed(){
    return new ProcessBuilder("/system/bin/id","-u").directory(new File("/"));
  }
  private static String deniedStart(){
    try {P75EngineStartRendezvous.startOrDeny(fixed());return "WRONG_SUCCESS";}
    catch(IOException denied){return denied.getMessage();}
  }
  private static void negativeMismatch(String kind){
    P37RemoteProcess p=remote();
    P184ChildStartReceipt r=issue(p,13);
    boolean accepted;
    if("process".equals(kind))accepted=r.consume(remote(),S,13);
    else if("session".equals(kind))accepted=r.consume(p,S.replace('a','b'),13);
    else if("owner".equals(kind))accepted=r.consume(p,S,14);
    else throw new AssertionError("unknown");
    yes(!accepted,"wrong_"+kind+"_rejected");
    yes(r.isConsumed(),"wrong_"+kind+"_burned");
    yes(!r.consume(p,S,13),"wrong_"+kind+"_cannot_retry");
  }
  private static void p75Roundtrip(boolean quickExit)throws Exception{
    final long epoch=quickExit?102:101;
    P75EngineStartRendezvous.armForVerifiedChildReceipt(S,epoch);
    AtomicReference<Process> result=new AtomicReference<>();
    AtomicReference<Throwable> failure=new AtomicReference<>();
    Thread engine=new Thread(()->{
      try {
        P75EngineStartRendezvous.claimOnEngineThread(S);
        result.set(P75EngineStartRendezvous.startOrDeny(fixed()));
      }catch(Throwable t){failure.set(t);}
    },"p184-fixed-argv-engine-fixture");
    engine.start();
    yes(P75EngineStartRendezvous.awaitOriginalBridgeEntered(2500),"p75_waiting_for_receipt");
    P37RemoteProcess p=remote();
    yes(!P75EngineStartRendezvous.authenticatedChildStarted(S,p,UID,u->u==UID),
        "legacy_uid_based_callback_denied_in_receipt_mode");
    P184ChildStartReceipt stale=issue(p,epoch-1);
    yes(!P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(stale,p),
        "wrong_epoch_receipt_denied");
    yes(stale.isConsumed(),"wrong_epoch_receipt_burned");
    P184ChildStartReceipt good=issue(p,epoch);
    if(quickExit)yes(p.onAuthenticatedExit(UID,S,0),"quick_exit_before_delivery_allowed");
    yes(P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(good,p),
        "verified_receipt_delivered");
    yes(!P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(good,p),
        "verified_receipt_replay_denied");
    engine.join(2600);
    yes(!engine.isAlive() && failure.get()==null,"engine_unblocked");
    yes(result.get()==p,"exact_same_process_identity_delivered");
    yes(!P75EngineStartRendezvous.isArmed(),"rendezvous_consumed");
  }

  public static void main(String[] ignored)throws Exception {
    yes(Modifier.isFinal(P184ChildStartReceipt.class.getModifiers()),"receipt_final");
    Constructor<?>[] ctors=P184ChildStartReceipt.class.getDeclaredConstructors();
    yes(ctors.length==1 && !Modifier.isPublic(ctors[0].getModifiers()),
        "no_public_receipt_factory");
    P37RemoteProcess p=remote();
    P184ChildStartReceipt a=issue(p,4);
    yes(a.consume(p,S,4),"valid_receipt");
    yes(a.isConsumed(),"receipt_burned_after_valid");
    yes(!a.consume(p,S,4),"replay_denied");
    negativeMismatch("process");
    negativeMismatch("session");
    negativeMismatch("owner");

    AtomicBoolean live=new AtomicBoolean(true);
    P184ChildStartReceipt revokedIssuer=new P184ChildStartReceipt(remote(),UID,S,5,live::get);
    live.set(false);
    yes(!revokedIssuer.consume(remote(),S,5),"process_mismatch_precedes_issuer_false");
    yes(revokedIssuer.isConsumed(),"issuer_mismatch_burned");
    P37RemoteProcess b=remote();
    P184ChildStartReceipt denied=new P184ChildStartReceipt(b,UID,S,6,()->false);
    yes(!denied.consume(b,S,6),"issuer_not_live_denied");
    P184ChildStartReceipt threw=new P184ChildStartReceipt(b,UID,S,6,
        ()->{throw new IllegalStateException("revoked");});
    yes(!threw.consume(b,S,6),"issuer_exception_fails_closed");

    P184ChildStartReceipt closed=issue(b,6);
    closed.revoke();
    yes(!closed.consume(b,S,6),"revoked_receipt_denied");
    yes(closed.isConsumed(),"revoked_receipt_burned");

    P37RemoteProcess finished=remote();
    yes(finished.onAuthenticatedExit(UID,S,0),"remote_exit_auth");
    P184ChildStartReceipt exited=issue(finished,7);
    yes(exited.consume(finished,S,7),"legitimate_rapid_exit_accepted");

    P37RemoteProcess lost=remote();
    P184ChildStartReceipt failed=issue(lost,8);
    lost.onTransportLost();
    yes(!failed.consume(lost,S,8),"binder_lost_denied");

    AtomicInteger winners=new AtomicInteger();
    P37RemoteProcess parallel=remote();
    P184ChildStartReceipt once=issue(parallel,9);
    CountDownLatch ready=new CountDownLatch(12);
    CountDownLatch fire=new CountDownLatch(1);
    Thread[] threads=new Thread[12];
    for(int i=0;i<threads.length;i++){
      threads[i]=new Thread(()->{
        ready.countDown();
        try{
          if(fire.await(3,TimeUnit.SECONDS)&&once.consume(parallel,S,9))
            winners.incrementAndGet();
        }catch(InterruptedException stopped){Thread.currentThread().interrupt();}
      },"p184-race-"+i);
      threads[i].start();
    }
    yes(ready.await(3,TimeUnit.SECONDS),"race_threads_ready");
    fire.countDown();
    for(Thread th:threads)th.join(2000);
    yes(winners.get()==1,"exactly_one_concurrent_consumer");
    yes(once.isConsumed(),"concurrency_burned");

    boolean invalid=false;
    try{new P184ChildStartReceipt(remote(),UID,"bad",10,()->true);}
    catch(IllegalArgumentException e){invalid=true;}
    yes(invalid,"invalid_session_cannot_mint");
    invalid=false;
    try{new P184ChildStartReceipt(remote(),UID,S,0,()->true);}
    catch(IllegalArgumentException e){invalid=true;}
    yes(invalid,"invalid_owner_epoch_cannot_mint");
    invalid=false;
    try{new P184ChildStartReceipt(remote(),UID+1,S,10,()->true);}
    catch(IllegalArgumentException e){invalid=true;}
    yes(invalid,"wrong_proxy_uid_cannot_mint");

    yes(!P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(issue(remote(),1),remote()),
        "not_armed_denied");
    p75Roundtrip(false);
    p75Roundtrip(true);
    yes("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK".equals(deniedStart()),
        "unarmed_original_bridge_denies");

    P75EngineStartRendezvous.armForVerifiedChildReceipt(S,105);
    P75EngineStartRendezvous.cancelSession("BINDER_LOST");
    yes(!P75EngineStartRendezvous.isArmed(),"binder_lost_cancels_verified_mode");
    P75EngineStartRendezvous.armForVerifiedChildReceipt(S,106);
    yes(!P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(issue(remote(),106),remote()),
        "receipt_cannot_handoff_without_waiting_engine_thread");
    P75EngineStartRendezvous.cancelSession("CANCELLED");
    yes(!P75EngineStartRendezvous.isArmed(),"cancel_succeeds");

    System.out.println("P184_PACKAGE_PRIVATE_PLATFORM_ISSUER_ONLY=PASS_SOURCE_BOUNDARY");
    System.out.println("P184_OWNER_EPOCH_EXACT_PROCESS_ONE_USE_RACE=PASS");
    System.out.println("P184_P75_RECEIPT_MODE_LEGACY_UID_CALLBACK_DENIED=PASS");
    System.out.println("P184_JAVA8_NEGATIVE_AND_THREAD_TEST=PASS assertions="+count);
    System.out.println("P184_FRAMEWORK_MESSAGE_SENDING_UID=REQUIRES_ANDROID_TEST");
    System.out.println("P184_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED");
  }
}
