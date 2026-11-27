package com.dsh.android.p102;

import com.dsh.android.p71.P71ToolReplyOnce;

/**
 * P102 trusted native-only synthetic tool approval boundary.
 *
 * One host-authenticated isolated worker session, at most one request,
 * explicit trusted native UI approval, exactly one terminal receipt.
 * This component has NO original DSH/Node/EngineManager production hook.
 * Binder identity MUST be read by the Android port from Message.sendingUid.
 */
public final class P102TrustedToolGate {
  public interface MonotonicClock { long elapsedRealtimeMs(); }
  public interface IsolatedUidVerifier { boolean isIsolatedUid(int uid); }
  public interface TrustedExecutor { boolean executeFixedRead(String name,String canonicalArgs); }
  public interface TerminalSink { void onTerminal(P71ToolReplyOnce.Terminal terminal); }
  /** Trusted host-only live original SessionStore/ToolRuntime ownership proof. */
  public interface OriginalCallVerifier {
    boolean isAcceptedCurrentToolCall(String originalSessionId,String originalCallId);
  }
  public enum Decision { PENDING_NATIVE_APPROVAL, REJECTED, EXPIRED, DISPATCHED }

  public static final String TOOL="read_synthetic_fixture";
  public static final String FIXED_ARGS="{\"query\":\"fixture\"}";
  public static final long APPROVAL_WINDOW_MS=10_000L;

  private final int uid;
  private final String session;
  private final MonotonicClock clock;
  private final IsolatedUidVerifier verifier;
  private final TrustedExecutor executor;
  private final TerminalSink terminalSink;
  private final OriginalCallVerifier originalCallVerifier;
  private boolean dead,requestSeen;
  private long acceptedAt;
  private P71ToolReplyOnce pending;
  private String pendingCallId;
  private String originalSessionId;

  public P102TrustedToolGate(int binderSendingUid,String hostMintedSession,
      MonotonicClock monotonicClock,IsolatedUidVerifier uidVerifier,
      TrustedExecutor trustedExecutor,TerminalSink sink,
      OriginalCallVerifier trustedOriginalCallVerifier){
    if(binderSendingUid<0||hostMintedSession==null||
       !hostMintedSession.matches("[a-f0-9]{64}")||
       monotonicClock==null||uidVerifier==null||trustedExecutor==null||sink==null||
       trustedOriginalCallVerifier==null||
       !uidVerifier.isIsolatedUid(binderSendingUid))
      throw new IllegalArgumentException("P102_HOST_AUTHENTICATED_BINDING_REQUIRED");
    uid=binderSendingUid;session=hostMintedSession;clock=monotonicClock;
    verifier=uidVerifier;executor=trustedExecutor;terminalSink=sink;
    originalCallVerifier=trustedOriginalCallVerifier;
  }

  /** Only accepted from real Messenger REQUEST using framework sendingUid. */
  public synchronized Decision accept(int frameworkUid,String sessionToken,
      String originalSession,String callId,String toolName,String canonicalArgs){
    if(dead||requestSeen)return Decision.REJECTED;
    if(frameworkUid!=uid||!session.equals(sessionToken)||!verifier.isIsolatedUid(frameworkUid)){
      revoke();return Decision.REJECTED;
    }
    requestSeen=true; // malformed attempts cannot be retried as a fresh call.
    if(originalSession==null||!originalSession.matches("[A-Za-z0-9_-]{1,128}")||
       callId==null||!callId.matches("[A-Za-z0-9_-]{1,96}")||
       !TOOL.equals(toolName)||!FIXED_ARGS.equals(canonicalArgs)){
      revoke();return Decision.REJECTED;
    }
    if(!originalCallValid(originalSession,callId)){
      revoke();return Decision.REJECTED;
    }
    originalSessionId=originalSession;
    pendingCallId=callId;
    acceptedAt=clock.elapsedRealtimeMs();
    if(acceptedAt<0){revoke();return Decision.REJECTED;}
    pending=new P71ToolReplyOnce(callId,terminalSink::onTerminal);
    return Decision.PENDING_NATIVE_APPROVAL;
  }

  private boolean originalCallValid(String sessionId,String callId){
    try{return originalCallVerifier.isAcceptedCurrentToolCall(sessionId,callId);}
    catch(RuntimeException invalid){return false;}
  }

  /**
   * Invoked ONLY by a trusted native Activity's explicit confirmation button.
   * There is deliberately no Binder/JS/Node message that invokes this.
   */
  /**
   * Native button permission is checked under this gate's monitor, but the
   * executor and terminal sink are NEVER run while holding that monitor.
   * A background worker must call this method; Android UI must not block.
   * Revocation during execution is terminal-unknown, never a safe retry.
   */
  public Decision onTrustedNativeApproval(String callId){
    final P71ToolReplyOnce current;
    final String original;
    final Decision early;
    synchronized(this){
      if(dead||pending==null||!pendingCallId.equals(callId)||pending.isCompleted())
        return Decision.REJECTED;
      current=pending;
      original=originalSessionId;
      final long now=clock.elapsedRealtimeMs();
      if(now<acceptedAt||now-acceptedAt>APPROVAL_WINDOW_MS){
        dead=true;
        early=Decision.EXPIRED;
      }else if(!originalCallValid(original,pendingCallId)){
        dead=true;
        early=Decision.REJECTED;
      }else{
        if(!current.markDispatched())return Decision.REJECTED;
        early=null;
      }
    }
    if(early!=null){
      // No lock inversion: terminal may enter the host Binder port.
      if(early==Decision.EXPIRED)current.deadlineElapsed();
      else current.executorConfirmedFailure("ORIGINAL_TURN_NOT_CURRENT");
      return early;
    }
    // A revoke arriving after dispatch but before actual execution wins.
    synchronized(this){
      if(dead||pending!=current)return Decision.DISPATCHED;
    }
    boolean ok=false;
    try{ok=executor.executeFixedRead(TOOL,FIXED_ARGS);}
    catch(RuntimeException ignored){ok=false;}
    final boolean stale;
    synchronized(this){
      // Revoke/timeout may already have delivered the one unknown terminal.
      if(dead||pending!=current)return Decision.DISPATCHED;
      stale=ok&&!originalCallValid(original,pendingCallId);
      dead=true;
    }
    if(stale)current.executorDispatchedOutcomeUnknown("ORIGINAL_TURN_STALE_AFTER_EXECUTION");
    else if(ok)current.executorConfirmedSuccess();
    else current.executorDispatchedOutcomeUnknown("EXECUTOR_REJECTED");
    return Decision.DISPATCHED;
  }

  public boolean expire(){
    final P71ToolReplyOnce current;
    synchronized(this){
      if(dead||pending==null||pending.isCompleted())return false;
      long now=clock.elapsedRealtimeMs();
      if(now>=acceptedAt && now-acceptedAt<=APPROVAL_WINDOW_MS)return false;
      dead=true;
      current=pending;
    }
    return current.deadlineElapsed();
  }

  /** Worker death, native UI background, or binding loss irrevocably revokes. */
  public void revoke(){
    final P71ToolReplyOnce current;
    synchronized(this){
      if(dead)return;
      dead=true;
      current=pending!=null&&!pending.isCompleted()?pending:null;
    }
    // The original tool body can still be executing; do not wait for it.
    if(current!=null)current.browserLost();
  }
  public synchronized boolean isTerminal(){return dead;}
  public synchronized boolean hasPendingApproval(){
    return !dead&&pending!=null&&!pending.isCompleted()&&!pending.wasDispatched();
  }
  public synchronized String pendingCallId(){return hasPendingApproval()?pendingCallId:null;}
  public synchronized boolean dispatched(){return pending!=null&&pending.wasDispatched();}
}
