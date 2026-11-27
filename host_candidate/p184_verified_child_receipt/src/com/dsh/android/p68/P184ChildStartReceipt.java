package com.dsh.android.p68;

import com.dsh.p37.P37RemoteProcess;
import java.util.function.BooleanSupplier;

/**
 * P184 - neutral Java8 one-use evidence produced by a real trusted P68
 * Android Binder intake ONLY AFTER framework Message.sendingUid + ordered
 * CHILD_STARTED have been authenticated. This class itself does NOT
 * authenticate a Binder UID, start a child or authorize production Node.
 *
 * Package-private construction: the P68 host intake is the issuer. Do not
 * expose a public factory, use a Bundle-supplied UID, or accept an
 * arbitrary untrusted BooleanSupplier as native attestation.
 */
public final class P184ChildStartReceipt {
  private static final long MAX_AGE_NANOS = 12_000_000_000L;
  private final P37RemoteProcess exactProcess;
  private final int frameworkIsolatedUid;
  private final String hostSession;
  private final long ownerEpoch;
  private final BooleanSupplier issuerStillValid;
  private final long issuedAt;
  private boolean consumed;

  P184ChildStartReceipt(P37RemoteProcess process, int platformSendingUid,
      String trustedSession, long trustedOwnerEpoch, BooleanSupplier trustedIssuerState) {
    if(process==null || platformSendingUid<=0 || trustedSession==null ||
       !trustedSession.matches("[0-9a-f]{64}") || trustedOwnerEpoch<=0 ||
       trustedIssuerState==null ||
       !process.matchesBoundIdentity(platformSendingUid,trustedSession))
      throw new IllegalArgumentException("P184_TRUSTED_ISSUER_REQUIRED");
    exactProcess=process;
    frameworkIsolatedUid=platformSendingUid;
    hostSession=trustedSession;
    ownerEpoch=trustedOwnerEpoch;
    issuerStillValid=trustedIssuerState;
    issuedAt=System.nanoTime();
  }

  /**
   * The first attempt burns the receipt even on mismatch. Only an exact P37
   * object, host-issued session and owner generation can consume it.
   * Legitimate immediate REMOTE_EXIT after CHILD_STARTED is permitted; an
   * identity, buffer or Binder transport failure is never accepted.
   */
  public synchronized boolean consume(P37RemoteProcess process, String session,
      long expectedOwnerEpoch) {
    if(consumed)return false;
    consumed=true;
    if(process!=exactProcess || !hostSession.equals(session) ||
       expectedOwnerEpoch!=ownerEpoch ||
       !exactProcess.matchesBoundIdentity(frameworkIsolatedUid,hostSession))
      return false;
    long elapsed=System.nanoTime()-issuedAt;
    if(elapsed<0 || elapsed>MAX_AGE_NANOS)return false;
    P37RemoteProcess.TerminalReason state=exactProcess.terminalReason();
    if(state!=P37RemoteProcess.TerminalReason.RUNNING &&
       state!=P37RemoteProcess.TerminalReason.REMOTE_EXIT)return false;
    try {return issuerStillValid.getAsBoolean();}
    catch(RuntimeException missingNativeAuthority){return false;}
  }

  /** Binder death, forced stop, stale epoch and cancellation burn the permit. */
  public synchronized void revoke(){consumed=true;}

  public synchronized boolean isConsumed(){return consumed;}
}
