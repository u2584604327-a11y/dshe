package com.dsh.android.p195;

import com.dsh.android.p194.P194OriginalModeSeal;
import com.dsh.p37.P37RemoteProcess;
import java.io.IOException;
import java.lang.Process;
import java.lang.ProcessBuilder;

/**
 * P195 non-authoritative host-side lifecycle witness for exact P37 Process.
 * It observes the ORIGINAL coroutine's expected Process assignment, reader
 * thread, latch and authenticated stream EOF, but it cannot inject events
 * into EngineManager, grant launch permission or declare genuine Node READY.
 *
 * An original Android framework UID / P68-P184 receipt is NOT supplied or
 * authenticated by this Java8 fixture. P47 remains DENY for all modes.
 */
public final class P195OriginalCoroutineLifecycle implements AutoCloseable {
  private enum State {
    RETURNED, PROCESS_FIELD_ASSIGNED, READER_THREAD_STARTED,
    LATCH_WAIT_OBSERVED, READER_EOF, EXIT_CONFIRMED, REVOKED
  }
  private final P37RemoteProcess exact;
  private final int mode;
  private State state=State.RETURNED;
  private Thread reader;
  private boolean closed;

  private P195OriginalCoroutineLifecycle(P37RemoteProcess process,int exactMode) {
    exact=process;mode=exactMode;
  }

  /**
   * Only a same-thread, exact-ProcessBuilder P194 seal attempt is accepted.
   * A successful P149/P194 snapshot has NO authority to spawn or certify UID.
   * A clean rapid exit is valid; any transport/identity/buffer failure is not.
   */
  public static P195OriginalCoroutineLifecycle observeAfterReturnedProcess(
      P194OriginalModeSeal seal,ProcessBuilder capturedOriginalBuilder,
      int mode,String session,long ownerEpoch,long sequence,
      P37RemoteProcess handedOffProcess) throws IOException {
    if(seal==null)throw new IOException("P195_MISSING_P194_SEAL");
    // Burn the seal on every verification attempt, including invalid input.
    seal.verifyOnce(capturedOriginalBuilder,mode,session,ownerEpoch,sequence);
    if(handedOffProcess==null)
      throw new IOException("P195_NO_VERIFIED_P37_PROCESS");
    P37RemoteProcess.TerminalReason terminal=handedOffProcess.terminalReason();
    if(terminal!=P37RemoteProcess.TerminalReason.RUNNING &&
       terminal!=P37RemoteProcess.TerminalReason.REMOTE_EXIT)
      throw new IOException("P195_UNTRUSTED_OR_LOST_CHILD");
    return new P195OriginalCoroutineLifecycle(handedOffProcess,mode);
  }
  private void require(State expected,String error)throws IOException {
    if(closed||state==State.REVOKED||state!=expected){
      revoke();
      throw new IOException(error);
    }
  }
  private void healthy()throws IOException {
    P37RemoteProcess.TerminalReason terminal=exact.terminalReason();
    if(terminal!=P37RemoteProcess.TerminalReason.RUNNING &&
       terminal!=P37RemoteProcess.TerminalReason.REMOTE_EXIT) {
      state=State.REVOKED;closed=true;
      throw new IOException("P195_REMOTE_TRANSPORT_OR_CHILD_FAILED");
    }
  }
  /** Exact Java Process object originally returned to EngineManager only. */
  public synchronized void observeProcessFieldAssignment(Process process)throws IOException {
    require(State.RETURNED,"P195_PROCESS_FIELD_ORDER_OR_REPLAY");
    if(process!=exact){
      revoke();
      throw new IOException("P195_DIFFERENT_PROCESS_OBJECT");
    }
    healthy();
    state=State.PROCESS_FIELD_ASSIGNED;
  }
  /** A distinct, actually started reader Thread is mandatory. */
  public synchronized void observeReaderThreadStarted(Thread thread)throws IOException {
    require(State.PROCESS_FIELD_ASSIGNED,"P195_READER_ORDER_OR_REPLAY");
    if(thread==null||thread==Thread.currentThread()||!thread.isAlive()){
      revoke();
      throw new IOException("P195_READER_NOT_STARTED_OR_INVALID");
    }
    healthy();
    reader=thread;
    state=State.READER_THREAD_STARTED;
  }
  /** This is ONLY an observation; it never counts the real original latch. */
  public synchronized void observeLatchAwait()throws IOException {
    require(State.READER_THREAD_STARTED,"P195_LATCH_BEFORE_READER_DENIED");
    healthy();
    state=State.LATCH_WAIT_OBSERVED;
  }
  /** Called by the exact reader Thread AFTER an actual read() == -1. */
  public synchronized void observeReaderEOF(int actualReadResult)throws IOException {
    require(State.LATCH_WAIT_OBSERVED,"P195_EOF_ORDER_OR_REPLAY");
    if(actualReadResult!=-1 || Thread.currentThread()!=reader){
      revoke();
      throw new IOException("P195_EOF_NOT_FROM_AUTHENTIC_READER_RESULT");
    }
    healthy();
    state=State.READER_EOF;
  }
  /** Clean exit is not EngineManager READY and is never inferred from text. */
  public synchronized void observeAuthenticatedExit()throws IOException {
    require(State.READER_EOF,"P195_EXIT_BEFORE_READER_EOF");
    if(exact.terminalReason()!=P37RemoteProcess.TerminalReason.REMOTE_EXIT ||
       exact.isAlive()) {
      revoke();
      throw new IOException("P195_NO_AUTHENTICATED_REMOTE_EXIT");
    }
    state=State.EXIT_CONFIRMED;
  }
  /** The only statuses are source diagnostics. No HTTP/token READY shortcut. */
  public synchronized boolean hasProductionEngineReady(){return false;}
  public synchronized boolean isComplete(){return !closed && state==State.EXIT_CONFIRMED;}
  public synchronized boolean hasFailed(){return state==State.REVOKED;}
  public synchronized int observedOriginalMode(){return mode;}
  public synchronized boolean retainsExactProcess(Process process){return exact==process;}
  public synchronized void revoke(){state=State.REVOKED;closed=true;}
  @Override public synchronized void close(){revoke();}
}
