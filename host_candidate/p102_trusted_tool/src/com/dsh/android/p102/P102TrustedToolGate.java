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
  private boolean dead,requestSeen;
  private long acceptedAt;
  private P71ToolReplyOnce pending;
  private String pendingCallId;

  public P102TrustedToolGate(int binderSendingUid,String hostMintedSession,
      MonotonicClock monotonicClock,IsolatedUidVerifier uidVerifier,
      TrustedExecutor trustedExecutor,TerminalSink sink){
    if(binderSendingUid<0||hostMintedSession==null||
       !hostMintedSession.matches("[a-f0-9]{64}")||
       monotonicClock==null||uidVerifier==null||trustedExecutor==null||sink==null||
       !uidVerifier.isIsolatedUid(binderSendingUid))
      throw new IllegalArgumentException("P102_HOST_AUTHENTICATED_BINDING_REQUIRED");
    uid=binderSendingUid;session=hostMintedSession;clock=monotonicClock;
    verifier=uidVerifier;executor=trustedExecutor;terminalSink=sink;
  }

  /** Only accepted from real Messenger REQUEST using framework sendingUid. */
  public synchronized Decision accept(int frameworkUid,String sessionToken,
      String callId,String toolName,String canonicalArgs){
    if(dead||requestSeen)return Decision.REJECTED;
    if(frameworkUid!=uid||!session.equals(sessionToken)||!verifier.isIsolatedUid(frameworkUid)){
      revoke();return Decision.REJECTED;
    }
    requestSeen=true; // malformed attempts cannot be retried as a fresh call.
    if(callId==null||!callId.matches("[A-Za-z0-9_-]{1,96}")||
       !TOOL.equals(toolName)||!FIXED_ARGS.equals(canonicalArgs)){
      revoke();return Decision.REJECTED;
    }
    pendingCallId=callId;
    acceptedAt=clock.elapsedRealtimeMs();
    if(acceptedAt<0){revoke();return Decision.REJECTED;}
    pending=new P71ToolReplyOnce(callId,terminalSink::onTerminal);
    return Decision.PENDING_NATIVE_APPROVAL;
  }

  /**
   * Invoked ONLY by a trusted native Activity's explicit confirmation button.
   * There is deliberately no Binder/JS/Node message that invokes this.
   */
  public synchronized Decision onTrustedNativeApproval(String callId){
    if(dead||pending==null||!pendingCallId.equals(callId)||pending.isCompleted())
      return Decision.REJECTED;
    final long now=clock.elapsedRealtimeMs();
    if(now<acceptedAt||now-acceptedAt>APPROVAL_WINDOW_MS){
      pending.deadlineElapsed();dead=true;return Decision.EXPIRED;
    }
    if(!pending.markDispatched())return Decision.REJECTED;
    boolean ok=false;
    try{ok=executor.executeFixedRead(TOOL,FIXED_ARGS);}
    catch(RuntimeException ignored){ok=false;}
    if(ok)pending.executorConfirmedSuccess();
    else pending.executorConfirmedFailure("EXECUTOR_REJECTED");
    dead=true;
    return Decision.DISPATCHED;
  }

  public synchronized boolean expire(){
    if(dead||pending==null||pending.isCompleted())return false;
    long now=clock.elapsedRealtimeMs();
    if(now>=acceptedAt && now-acceptedAt<=APPROVAL_WINDOW_MS)return false;
    boolean accepted=pending.deadlineElapsed();dead=true;return accepted;
  }

  /** Worker death, native UI background, or binding loss irrevocably revokes. */
  public synchronized void revoke(){
    if(dead)return;
    dead=true;
    if(pending!=null&&!pending.isCompleted())pending.browserLost();
  }
  public synchronized boolean isTerminal(){return dead;}
  public synchronized boolean hasPendingApproval(){
    return !dead&&pending!=null&&!pending.isCompleted()&&!pending.wasDispatched();
  }
  public synchronized String pendingCallId(){return hasPendingApproval()?pendingCallId:null;}
  public synchronized boolean dispatched(){return pending!=null&&pending.wasDispatched();}
}
