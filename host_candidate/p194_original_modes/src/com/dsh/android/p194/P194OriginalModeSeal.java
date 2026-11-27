package com.dsh.android.p194;

import com.dsh.android.p149.P149OriginalBuilderWitness;
import java.io.IOException;
import java.lang.ProcessBuilder;
import java.security.SecureRandom;

/**
 * P194 nonproduction, host-private prelaunch shape/ownership seal for the
 * EXACT THREE original v138 EngineManager callsites. It cannot start a
 * process, mint a P184 Binder receipt, return a Process or declare Node READY.
 *
 * Source-only identity: Thread.currentThread() is NOT an Android Binder
 * platform attestation. Future trusted P47 adapter must derive the mode from
 * the exact DEX callsite and the epoch from the authenticated owner, NEVER a
 * Bundle, WebView page, API request or caller-supplied security label.
 */
public final class P194OriginalModeSeal implements AutoCloseable {
  public static final int PROBE_BOOT=1;
  public static final int RUN_DUMP_CONFIG=2;
  public static final int START=3;
  public static final long MAX_LIFETIME_NANOS=12_000_000_000L;

  private final P149OriginalBuilderWitness.Witness witness;
  private final Thread exactOwnerThread;
  private final ProcessBuilder exactBuilder;
  private final String hostSession;
  private final long ownerEpoch, invocationSeq, createdNanos;
  private final int mode;
  private boolean used, closed;

  private static void checkModeAndStreams(ProcessBuilder b,int mode)
      throws IOException {
    if(mode!=PROBE_BOOT && mode!=RUN_DUMP_CONFIG && mode!=START)
      throw new IOException("P194_UNKNOWN_ORIGINAL_MODE");
    if(b==null || b.command()==null || b.command().isEmpty() ||
       b.command().size()>128 || b.directory()==null)
      throw new IOException("P194_MISSING_ORIGINAL_LAUNCH_SHAPE");
    if(b.redirectErrorStream()!=(mode!=RUN_DUMP_CONFIG))
      throw new IOException("P194_ORIGINAL_STDERR_MODE_DRIFT");
    if(b.redirectInput()!=ProcessBuilder.Redirect.PIPE ||
       b.redirectOutput()!=ProcessBuilder.Redirect.PIPE ||
       b.redirectError()!=ProcessBuilder.Redirect.PIPE)
      throw new IOException("P194_ORIGINAL_PIPE_REDIRECT_DRIFT");
  }

  /**
   * Test/host-preflight only. A captured witness does NOT grant launch
   * permission: the original P47 gates must still throw DENY for every mode.
   */
  public static P194OriginalModeSeal capture(ProcessBuilder exactOriginalBuilder,
      int trustedMode, String hostMintedSession,
      long trustedOwnerEpoch, long trustedCallSequence) throws IOException {
    if(hostMintedSession==null ||
       !hostMintedSession.matches("[a-f0-9]{64}") ||
       trustedOwnerEpoch<=0 || trustedCallSequence<=0)
      throw new IOException("P194_HOST_OWNER_GENERATION_REQUIRED");
    checkModeAndStreams(exactOriginalBuilder,trustedMode);
    return new P194OriginalModeSeal(exactOriginalBuilder,trustedMode,
        hostMintedSession,trustedOwnerEpoch,trustedCallSequence);
  }
  private P194OriginalModeSeal(ProcessBuilder b,int m,String s,long epoch,long seq)
      throws IOException {
    // Capture the sealed immutable data and original object/thread identity.
    // The P149 constructor checks full argv/cwd/environment/redirect fields,
    // generating a fresh HMAC key which will be wiped after one comparison.
    exactOwnerThread=Thread.currentThread();
    exactBuilder=b;
    mode=m;
    hostSession=s;
    ownerEpoch=epoch;
    invocationSeq=seq;
    witness=P149OriginalBuilderWitness.capture(b,m,s,seq);
    createdNanos=System.nanoTime();
  }

  /**
   * One single comparison; first valid OR INVALID attempt irrevocably
   * closes and erases the P149 witness. Void return: this is NO permission.
   */
  public synchronized void verifyOnce(ProcessBuilder sameOriginalBuilder,
      int sameTrustedMode,String sameHostSession,long sameOwnerEpoch,
      long sameCallSequence) throws IOException {
    if(used || closed)throw new IOException("P194_ALREADY_CONSUMED_OR_REVOKED");
    used=true;
    try {
      long age=System.nanoTime()-createdNanos;
      if(age<0 || age>MAX_LIFETIME_NANOS)
        throw new IOException("P194_OWNER_LEASE_EXPIRED");
      if(Thread.currentThread()!=exactOwnerThread)
        throw new IOException("P194_DIFFERENT_OWNER_THREAD");
      if(sameOriginalBuilder!=exactBuilder)
        throw new IOException("P194_DIFFERENT_PROCESSBUILDER_OBJECT");
      if(sameTrustedMode!=mode || sameOwnerEpoch!=ownerEpoch ||
         sameCallSequence!=invocationSeq || !hostSession.equals(sameHostSession))
        throw new IOException("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT");
      checkModeAndStreams(sameOriginalBuilder,sameTrustedMode);
      witness.matchOnce(sameOriginalBuilder,sameTrustedMode,
          sameHostSession,sameCallSequence);
    }finally{close();}
  }

  /** Cancel/background/Binder death must revoke the original owner lease. */
  @Override public synchronized void close() {
    if(!closed){closed=true;used=true;witness.close();}
  }

  public synchronized boolean isTerminal(){return closed;}
}
