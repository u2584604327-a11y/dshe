package com.dsh.android.p184;

import android.app.Activity;
import android.os.Messenger;
import com.dsh.android.p48.P48HostProcessProbe;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.android.p75.P75EngineStartRendezvous;
import com.dsh.p37.P37RemoteProcess;
import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * P184 Android35 real isolated Binder one-use receipt test ONLY.
 * Runs only inside temporary original-v138-derived com.dsh.android/P43 test.
 * A dedicated host thread is a synthetic P75 caller, NOT original EngineManager
 * or the original P40/ProcessBuilder bridge, which remains DENY.
 */
public final class P184AndroidReceiptProbe implements AutoCloseable {
  public interface Reporter { void report(String fixedStatus); }
  private static final long FIXTURE_EPOCH=184L;
  private final Activity host;
  private final Reporter output;
  private final String hostSession;
  private final Messenger isolated;
  private final AtomicBoolean closed=new AtomicBoolean();
  private volatile P37RemoteProcess verifiedProcess;
  private P48HostProcessProbe child;
  private Thread engine;

  public P184AndroidReceiptProbe(Activity originalHost,Messenger verifiedWorker,
      String hostMintedSession,Reporter reporter) {
    if(originalHost==null || verifiedWorker==null || reporter==null ||
       !"com.dsh.android".equals(originalHost.getPackageName()) ||
       !"com.dsh.android.p43.P43ProbeActivity".equals(originalHost.getClass().getName()) ||
       hostMintedSession==null || !hostMintedSession.matches("[a-f0-9]{64}"))
      throw new SecurityException("P184_FIXED_ORIGINAL_EMULATOR_ONLY");
    host=originalHost;
    isolated=verifiedWorker;
    hostSession=hostMintedSession;
    output=reporter;
  }
  private void status(String s){
    if(!closed.get())host.runOnUiThread(()->{
      if(!closed.get())output.report(s);
    });
  }

  /** This never calls the original production P40 EngineManager start path. */
  public void start() {
    if(child!=null || engine!=null)throw new IllegalStateException("P184_ALREADY_STARTED");
    P75EngineStartRendezvous.armForVerifiedChildReceipt(hostSession,FIXTURE_EPOCH);
    engine=new Thread(()->{
      try{
        P75EngineStartRendezvous.claimOnEngineThread(hostSession);
        ProcessBuilder fixed=new ProcessBuilder("/system/bin/id","-u");
        fixed.directory(new File("/"));
        java.lang.Process delivered=P75EngineStartRendezvous.startOrDeny(fixed);
        // The P68-minted receipt must deliver the identical P37 object, not
        // a second unsandboxed process, a bogus process or another session.
        if(!closed.get() && delivered==verifiedProcess &&
           delivered instanceof P37RemoteProcess) {
          status("P184_ANDROID35_P75_CROSS_THREAD_EXACT_PROCESS=PASS");
          status("P184_ANDROID35_REAL_P40_ORIGINAL_COROUTINE=NOT_INVOKED");
        }else status("P184_ANDROID35_P75_PROCESS_MISMATCH=DENY");
      }catch(Exception denied){
        status("P184_ANDROID35_P75_CROSS_THREAD_FAILED=DENY");
      }
    },"p184-synthetic-original-engine-thread");
    engine.start();
    try {
      if(!P75EngineStartRendezvous.awaitOriginalBridgeEntered(3000)){
        P75EngineStartRendezvous.cancelSession("TIMEOUT");
        status("P184_ANDROID35_P75_DID_NOT_WAIT=DENY");
        return;
      }
    }catch(InterruptedException stop){
      Thread.currentThread().interrupt();
      P75EngineStartRendezvous.cancelSession("CANCELLED");
      status("P184_ANDROID35_P75_INTERRUPTED=DENY");
      return;
    }
    status("P184_ANDROID35_P75_FIXED_ENGINE_THREAD_WAITING=PASS");
    child=new P48HostProcessProbe(isolated,hostSession,
        new P48HostProcessProbe.Listener(){
          @Override public void report(String s){
            // Keep existing P48 evidence only; do not promote synthetic
            // fixed UID output to real production EngineManager READY.
            if("P184_P68_REAL_FRAMEWORK_RECEIPT_DELIVERED=PASS".equals(s))
              status("P184_ANDROID35_P68_FRAMEWORK_RECEIPT=PASS");
            if("P48_P37_PROCESS_STDOUT_EOF_WAIT_EXIT=PASS".equals(s))
              status("P184_ANDROID35_FIXED_ISOLATED_CHILD_EXIT=PASS");
          }
          @Override public void fail(String reason){
            status("P184_ANDROID35_P48_CHILD_TRANSPORT=DENY");
          }
        },false,null,true,(process,receipt)->{
          if(closed.get())throw new SecurityException("P184_ACTIVITY_CLOSED");
          if(receipt==null || process==null)throw new SecurityException("P184_NO_RECEIPT");
          verifiedProcess=process;
          // The old tuple UID/session/verifier is deliberately unusable in
          // verified-receipt mode, even when these labels happen to match.
          if(P75EngineStartRendezvous.authenticatedChildStarted(
               hostSession,process,android.os.Process.myUid(),
               android.os.Process::isIsolatedUid))
            throw new SecurityException("P184_LEGACY_UID_ONLY_BYPASS");
          status("P184_ANDROID35_P75_LEGACY_BYPASS_DENIED=PASS");
          if(!P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(
                 receipt,process))
            throw new SecurityException("P184_VERIFIED_RECEIPT_DENIED");
          status("P184_ANDROID35_P68_TO_P75_ONCE=PASS");
          if(P75EngineStartRendezvous.authenticatedChildStartedWithReceipt(
                 receipt,process))
            throw new SecurityException("P184_REPLAY_ACCEPTED");
          status("P184_ANDROID35_REPLAY_DENIED=PASS");
        },FIXTURE_EPOCH);
    child.start();
  }

  @Override public void close(){
    if(closed.compareAndSet(false,true)){
      if(child!=null)child.close();
      P75EngineStartRendezvous.cancelSession("BINDER_LOST");
    }
  }
}
