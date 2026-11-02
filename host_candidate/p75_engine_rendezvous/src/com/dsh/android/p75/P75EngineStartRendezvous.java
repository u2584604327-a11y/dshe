package com.dsh.android.p75;

import com.dsh.p37.P37RemoteProcess;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * P75: bounded cross-thread original-P40 call -> authenticated P68/P37 handoff.
 * Only the permissionless P51 sidecar fixed /system/bin/id -u is authorized.
 * The engine caller never starts a host Process; the Android Binder callback
 * must first verify actual sendingUid, host session and P53 CHILD_STARTED.
 * This is NOT real original EngineManager coroutine or production Node.
 */
public final class P75EngineStartRendezvous {
  private static final Object LOCK=new Object();
  private static final String DENY="P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK";
  private static final long WAIT_MILLIS=12000;
  private static Pending pending;
  // A claim belongs to this exact pending lease object, not a reusable
  // session string. Cancellation plus accidental host-session ID reuse must
  // NEVER reactivate a stale engine-thread permit.
  private static final ThreadLocal<Pending> trustedCall=new ThreadLocal<>();
  private static final class Pending {
    final String session;
    final CountDownLatch entered=new CountDownLatch(1);
    final CountDownLatch answered=new CountDownLatch(1);
    boolean waiting,terminal;
    // One lease can belong to one actual engine call thread only.
    // Session contents do not prove thread ownership.
    Thread claimedThread;
    P37RemoteProcess proxy;
    Pending(String s){session=s;}
  }
  private P75EngineStartRendezvous(){}
  public static void armFromTrustedHost(String hostGeneratedSession) {
    if(hostGeneratedSession==null ||
       !hostGeneratedSession.matches("[0-9a-f]{64}"))
      throw new SecurityException("P75_HOST_SESSION_REQUIRED");
    synchronized(LOCK) {
      if(pending!=null)throw new SecurityException("P75_ALREADY_ARMED");
      pending=new Pending(hostGeneratedSession);
    }
  }
  /** Test host must bind the exact coroutine's intended thread; not Binder thread. */
  public static void claimOnEngineThread(String session){
    synchronized(LOCK) {
      if(pending==null || pending.terminal ||
         !pending.session.equals(session) || trustedCall.get()!=null ||
         pending.claimedThread!=null)
        throw new SecurityException("P75_UNAUTHORIZED_ENGINE_THREAD");
      pending.claimedThread=Thread.currentThread();
      trustedCall.set(pending);
    }
  }
  public static boolean awaitOriginalBridgeEntered(long timeoutMillis)
      throws InterruptedException {
    Pending p;
    synchronized(LOCK){p=pending;}
    return p!=null && timeoutMillis>0 && timeoutMillis<=5000 &&
           p.entered.await(timeoutMillis,TimeUnit.MILLISECONDS);
  }
  public static boolean authenticatedChildStarted(
      String hostGeneratedSession, P37RemoteProcess remote,
      int platformSendingUid,P37RemoteProcess.IsolatedUidVerifier frameworkUidVerifier){
    synchronized(LOCK){
      Pending p=pending;
      if(p==null || p.terminal || !p.waiting || p.proxy!=null ||
         !p.session.equals(hostGeneratedSession) || remote==null ||
         !remote.isAlive() || platformSendingUid<0 || frameworkUidVerifier==null ||
         !frameworkUidVerifier.isIsolatedUid(platformSendingUid) ||
         // P168: exact P37 proxy identity must match the Binder UID and
         // host-minted pending session, not just caller-supplied labels.
         // Does NOT authorize arbitrary Node argv, bypass P68, or confer
         // production EngineManager access.
         !remote.matchesBoundIdentity(platformSendingUid,hostGeneratedSession))
        return false;
      // Caller MUST be P48's onLiveProxy callback after P68 verified
      // Binder Message.sendingUid, session, ordering and CHILD_STARTED.
      p.proxy=remote;
      p.answered.countDown();
      return true;
    }
  }
  public static Process startOrDeny(ProcessBuilder requested) throws IOException {
    Pending p;
    Pending claimed=trustedCall.get();
    trustedCall.remove();
    synchronized(LOCK) {
      p=pending;
      if(p==null || p.terminal || claimed!=p ||
         p.claimedThread!=Thread.currentThread() || p.waiting)
        throw new IOException(DENY);
      // Reject unknown engine argv BEFORE any waiting or receipt of child.
      List<String> args=requested==null?null:requested.command();
      File cwd=requested==null?null:requested.directory();
      if(args==null || args.size()!=2 ||
         !"/system/bin/id".equals(args.get(0)) ||
         !"-u".equals(args.get(1)) ||
         cwd==null || !"/".equals(cwd.getAbsolutePath()) ||
         requested.redirectErrorStream()) {
        p.terminal=true;
        pending=null;
        p.answered.countDown();
        throw new IOException("P75_PRODUCTION_ARGV_NOT_AUTHORIZED");
      }
      p.waiting=true;
      p.entered.countDown();
    }
    boolean got;
    try{got=p.answered.await(WAIT_MILLIS,TimeUnit.MILLISECONDS);}
    catch(InterruptedException cancelled){
      Thread.currentThread().interrupt();
      // P177: this engine thread owns p, NOT whatever global pending
      // might have been created after its own lease was cancelled.
      // The old cancelSession() could revoke a newer (even identical
      // session-text) lease when an abandoned old thread wakes late.
      cancelExactPending(p);
      throw new IOException("P75_ENGINE_START_INTERRUPTED",cancelled);
    }
    P37RemoteProcess abandoned=null;
    Process returned=null;
    synchronized(LOCK){
      // REMOTE_EXIT is legitimate after CHILD_STARTED; identity/transport
      // failures are not. A child can race an expired await() before LOCK.
      P37RemoteProcess.TerminalReason reason=p.proxy==null ? null : p.proxy.terminalReason();
      if(!got || p.terminal || p.proxy==null ||
         (reason!=P37RemoteProcess.TerminalReason.RUNNING &&
          reason!=P37RemoteProcess.TerminalReason.REMOTE_EXIT)) {
        if(pending==p)pending=null;
        p.terminal=true;
        abandoned=p.proxy;
        p.proxy=null;
      } else {
        returned=p.proxy;
        p.terminal=true;
        if(pending==p)pending=null;
      }
    }
    // Remote callbacks may reenter the rendezvous; never stop under LOCK.
    if(abandoned!=null)abandoned.destroyForcibly();
    if(returned==null)throw new IOException("P75_CHILD_ACK_MISSING_OR_TIMEOUT");
    return returned;
  }
  // Identity-scoped interruption cleanup: an obsolete coroutine's
  // cancellation may only affect its own exact pending generation.
  // In particular it may not tear down a new lease after host re-arming.
  private static void cancelExactPending(Pending target){
    if(target==null)return;
    P37RemoteProcess undelivered=null;
    synchronized(LOCK) {
      if(pending!=target)return;
      target.terminal=true;
      // A previously authenticated child must not survive cancellation
      // before the engine thread actually receives its Process facade.
      undelivered=target.proxy;
      target.proxy=null;
      target.answered.countDown();
      pending=null;
    }
    // Never invoke a potentially reentrant remote-control callback under LOCK.
    if(undelivered!=null)undelivered.destroyForcibly();
  }
  public static void cancelSession(String category){
    if(!"CANCELLED".equals(category) && !"BINDER_LOST".equals(category) &&
       !"ACTIVITY_GONE".equals(category) && !"TIMEOUT".equals(category))
      throw new IllegalArgumentException("P75_BOUNDED_REASON_REQUIRED");
    Pending target;
    synchronized(LOCK){target=pending;}
    cancelExactPending(target);
  }
  public static boolean isArmed() {
    synchronized(LOCK){return pending!=null;}
  }
}
