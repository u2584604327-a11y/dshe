package com.dsh.p37;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Source-only, host-side Java Process facade for a remote isolated Android Node.
 * This is NOT a process launcher, Android Binder implementation, or an original
 * EngineManager patch. A trusted native adapter must validate the framework
 * Binder sender UID and supply a host-generated session before constructing it.
 * Pipe endpoints are supplied and owned by the trusted transport. Command,
 * filesystem and tool authorization belong to that transport's launch lease.
 */
public final class P37RemoteProcess extends Process {
  /** Owned pipe endpoints supplied by the authenticated host transport.
   * The child must already have merged stderr when merged() is selected.
   * Pipe writes provide backpressure without buffering data on Binder threads.
   */
  public static final class Stdio implements Closeable {
    private final OutputStream input;
    private final InputStream output;
    private final InputStream error;
    private final boolean merged;

    private Stdio(OutputStream input, InputStream output, InputStream error,
        boolean merged) {
      if (input == null || output == null || error == null || output == error)
        throw new IllegalArgumentException("distinct owned pipe endpoints required");
      this.input = input;
      this.output = output;
      this.error = error;
      this.merged = merged;
    }
    public static Stdio split(OutputStream input, InputStream output,
        InputStream error) {
      return new Stdio(input, output, error, false);
    }
    public static Stdio merged(OutputStream input, InputStream output) {
      return new Stdio(input, output, new ByteArrayInputStream(new byte[0]), true);
    }
    @Override public void close() throws IOException {
      IOException failure = null;
      for (Closeable stream : new Closeable[] {input, output, error}) {
        try { stream.close(); }
        catch (IOException closed) {
          if (failure == null) failure = closed;
          else failure.addSuppressed(closed);
        }
      }
      if (failure != null) throw failure;
    }
  }
  public interface IsolatedUidVerifier {
    boolean isIsolatedUid(int frameworkUid);
  }
  public interface RemoteControl {
    void requestGracefulStop();
    void requestForceStop();
  }
  public enum TerminalReason {
    RUNNING, REMOTE_EXIT, TRANSPORT_LOST, IDENTITY_MISMATCH,
    BUFFER_OVERFLOW, STOP_TIMEOUT, REMOTE_CONTROL_FAILURE
  }
  public static final int BUFFER_BYTES = 65536;
  public static final int MAX_FRAME_BYTES = 4096;
  public static final int SUPERVISOR_FAILURE_EXIT_CODE = 125;
  private final int boundUid;
  private final String session;
  private final IsolatedUidVerifier uidVerifier;
  private final RemoteControl control;
  private final Stdio pipes;
  /** Only trusted host constructor may opt in; legacy P51 stays split. */
  private final boolean mergeErrorToOutput;
  private final BoundedStream stdout = new BoundedStream(BUFFER_BYTES);
  private final BoundedStream stderr = new BoundedStream(BUFFER_BYTES);
  private final CountDownLatch exited = new CountDownLatch(1);
  private final Object lock = new Object();
  private volatile TerminalReason reason = TerminalReason.RUNNING;
  private int exitCode = SUPERVISOR_FAILURE_EXIT_CODE;
  private boolean stopSent = false;
  private boolean killSent = false;

  public P37RemoteProcess(int authenticatedWorkerUid, String hostSession,
      IsolatedUidVerifier verifier, RemoteControl remoteControl) {
    this(authenticatedWorkerUid, hostSession, verifier, remoteControl, false);
  }
  /** P141: reproduces original ProcessBuilder.redirectErrorStream(true).
   * Binder frame order must already be validated by P53/P67 before routing.
   * Neither true nor false grants original Node argv or EngineManager READY.
   */
  public P37RemoteProcess(int authenticatedWorkerUid, String hostSession,
      IsolatedUidVerifier verifier, RemoteControl remoteControl,
      boolean trustedHostRequestsMergedStderr) {
    this(authenticatedWorkerUid, hostSession, verifier, remoteControl,
        trustedHostRequestsMergedStderr, null);
  }

  /** Host-only pipe transport. Construction takes ownership after validation.
   * The caller must verify CHILD_STARTED, lease and generation before handoff.
   * Binder carries lifecycle frames while the owned pipes carry stream data.
   */
  public P37RemoteProcess(int authenticatedWorkerUid, String hostSession,
      IsolatedUidVerifier verifier, RemoteControl remoteControl, Stdio streams) {
    this(authenticatedWorkerUid, hostSession, verifier, remoteControl,
        requireStreams(streams).merged, streams);
  }
  private static Stdio requireStreams(Stdio streams) {
    if (streams == null) throw new IllegalArgumentException("owned pipes required");
    return streams;
  }
  private P37RemoteProcess(int authenticatedWorkerUid, String hostSession,
      IsolatedUidVerifier verifier, RemoteControl remoteControl,
      boolean trustedHostRequestsMergedStderr, Stdio streams) {
    if (verifier == null || remoteControl == null || hostSession == null ||
        !hostSession.matches("[a-f0-9]{64}") || authenticatedWorkerUid < 0 ||
        !verifier.isIsolatedUid(authenticatedWorkerUid)) {
      throw new IllegalArgumentException("trusted isolated session required");
    }
    boundUid = authenticatedWorkerUid;
    session = hostSession;
    uidVerifier = verifier;
    control = remoteControl;
    pipes = streams;
    mergeErrorToOutput = trustedHostRequestsMergedStderr;
    // With redirectErrorStream(true), Java Process.getErrorStream() is EOF;
    // no reader may wait forever for an unpopulated error pipe.
    if (mergeErrorToOutput) stderr.finish(false);
  }

  /** Pure identity comparison; NOT proof that any caller controls Binder.
   * Trust still requires a separately validated platform Message.sendingUid
   * and the original P68/P53 authenticated child-start event. No session
   * contents are exposed, and mismatch never tears down a live Process.
   */
  public boolean matchesBoundIdentity(int frameworkUid, String hostSession) {
    return frameworkUid == boundUid && session.equals(hostSession);
  }

  /** Caller MUST pass platform Message.sendingUid, never a Bundle UID. */
  private boolean authenticate(int frameworkUid, String incomingSession) {
    // UID verification belongs to the trusted native adapter, but a runtime
    // verifier failure must NOT escape a Binder callback with the remote
    // Process still RUNNING (and unread token-bearing READY bytes buffered).
    // Treat an unavailable/throwing verifier exactly as a rejected identity.
    // Never include the verifier exception or private session in logs.
    if (frameworkUid == boundUid && session.equals(incomingSession)) {
      try {
        if (uidVerifier.isIsolatedUid(frameworkUid)) return true;
      } catch (RuntimeException ignored) {
        // Invalidate below; do not let a framework lookup failure fail open.
      }
    }
    failClosed(TerminalReason.IDENTITY_MISMATCH);
    return false;
  }

  /** Nonblocking Binder callback; stream backpressure can NEVER block Binder. */
  public boolean onAuthenticatedStdout(int frameworkUid, String incomingSession,
      byte[] data) {
    return accept(frameworkUid, incomingSession, data, stdout);
  }
  public boolean onAuthenticatedStderr(int frameworkUid, String incomingSession,
      byte[] data) {
    // Frame acceptance and bounded buffering share the same host receive
    // order as STDOUT, including forged-identity and overflow revocation.
    return accept(frameworkUid, incomingSession, data,
        mergeErrorToOutput ? stdout : stderr);
  }
  private boolean accept(int uid, String incomingSession, byte[] data,
      BoundedStream stream) {
    if (!authenticate(uid, incomingSession)) return false;
    if (pipes != null) {
      failClosed(TerminalReason.TRANSPORT_LOST);
      return false;
    }
    // Serialize the final RUNNING check and frame enqueue with authenticated
    // EXIT. Otherwise EXIT can publish REMOTE_EXIT while a prior callback is
    // waiting for the stream monitor, then that callback can append a frame
    // after terminal publication. Preserve lock order: lock -> stream.
    boolean callKill;
    synchronized (lock) {
      if (reason != TerminalReason.RUNNING) return false;
      if (data != null && data.length >= 1 && data.length <= MAX_FRAME_BYTES &&
          stream.offer(data)) return true;
      // An invalid/full frame must publish BUFFER_OVERFLOW before EXIT can
      // commit REMOTE_EXIT. Never let a concurrent clean exit mask a
      // fail-closed transport violation or expose buffered READY bytes.
      callKill = failClosedUnderLock(TerminalReason.BUFFER_OVERFLOW);
    }
    // Remote control may reenter the proxy; invoke it only outside lock.
    if (callKill) requestForceStopSafely();
    return false;
  }

  public boolean onAuthenticatedExit(int frameworkUid, String incomingSession,
      int actualChildExitCode) {
    if (!authenticate(frameworkUid, incomingSession)) return false;
    synchronized (lock) {
      if (reason != TerminalReason.RUNNING) return false;
      exitCode = actualChildExitCode;
      reason = TerminalReason.REMOTE_EXIT;
      stdout.finish(false);
      stderr.finish(false);
      exited.countDown();
    }
    // Preserve unread stdout/stderr until their pipe writers close. Closing
    // the child input also releases writers when exit precedes their write.
    if (pipes != null) closeQuietly(pipes.input);
    return true;
  }
  /** Both binder death and worker unbind must invalidate this proxy. */
  public void onTransportLost() { failClosed(TerminalReason.TRANSPORT_LOST); }
  /** Trusted supervisor must schedule this if stop/kill ACK is absent. */
  public void onStopDeadlineExpired() { failClosed(TerminalReason.STOP_TIMEOUT); }
  public TerminalReason terminalReason() { return reason; }

  /** Caller holds lifecycle lock; terminal reason and stream discard are
   * one indivisible decision against authenticated EXIT. No remote callbacks.
   */
  private boolean failClosedUnderLock(TerminalReason cause) {
    if (reason != TerminalReason.RUNNING) return false;
    reason = cause;
    exitCode = SUPERVISOR_FAILURE_EXIT_CODE;
    stdout.finish(true); // Discard untrusted pending lines; never imply READY.
    stderr.finish(true);
    exited.countDown();
    if (!killSent) { killSent = true; return true; }
    return false;
  }
  private void requestForceStopSafely() {
    try { control.requestForceStop(); } catch (RuntimeException ignored) {
      // Failure is terminal; physical worker kill is NOT proven.
    }
  }
  private void failClosed(TerminalReason cause) {
    boolean callKill;
    synchronized (lock) { callKill = failClosedUnderLock(cause); }
    if (pipes != null && reason != TerminalReason.RUNNING &&
        reason != TerminalReason.REMOTE_EXIT) closeQuietly(pipes);
    if (callKill) requestForceStopSafely();
  }
  private static void closeQuietly(Closeable stream) {
    try { stream.close(); } catch (IOException ignored) {
      // The lifecycle reason records failure independently of stream close.
    }
  }
  @Override public InputStream getInputStream() {
    return pipes == null ? stdout : pipes.output;
  }
  @Override public InputStream getErrorStream() {
    return pipes == null ? stderr : pipes.error;
  }
  /** The legacy frame transport denies stdin. Owned pipes forward stdin and EOF. */
  @Override public OutputStream getOutputStream() {
    if (pipes != null) return pipes.input;
    return new OutputStream() {
      @Override public void write(int b) throws IOException {
        throw new IOException("P37_UNAUDITED_STDIN_DENIED");
      }
      @Override public void write(byte[] b, int o, int len) throws IOException {
        if (b == null) throw new NullPointerException();
        if (o < 0 || len < 0 || o > b.length - len)
          throw new IndexOutOfBoundsException();
        if (len != 0) throw new IOException("P37_UNAUDITED_STDIN_DENIED");
      }
    };
  }
  @Override public int waitFor() throws InterruptedException {
    exited.await();
    synchronized (lock) { return exitCode; }
  }
  @Override public boolean waitFor(long timeout, TimeUnit unit)
      throws InterruptedException {
    if (unit == null) throw new NullPointerException("unit");
    return exited.await(timeout, unit);
  }
  @Override public int exitValue() {
    synchronized (lock) {
      if (reason == TerminalReason.RUNNING) throw new IllegalThreadStateException();
      return exitCode;
    }
  }
  @Override public boolean isAlive() { return reason == TerminalReason.RUNNING; }
  @Override public void destroy() {
    synchronized (lock) {
      if (reason != TerminalReason.RUNNING || stopSent || killSent) return;
      stopSent = true;
    }
    try { control.requestGracefulStop(); }
    catch (RuntimeException bad) { failClosed(TerminalReason.REMOTE_CONTROL_FAILURE); }
  }
  @Override public Process destroyForcibly() {
    synchronized (lock) {
      if (reason != TerminalReason.RUNNING || killSent) return this;
      killSent = true;
    }
    try { control.requestForceStop(); }
    catch (RuntimeException bad) { failClosed(TerminalReason.REMOTE_CONTROL_FAILURE); }
    return this;
  }

  private static final class BoundedStream extends InputStream {
    private final byte[] buffer;
    private int first = 0, used = 0;
    private boolean done = false;
    // A local Process InputStream.close() must not kill the remote child.
    // Keep validating each authenticated bounded frame, then discard it.
    private boolean closedByReader = false;
    BoundedStream(int cap) { buffer = new byte[cap]; }
    synchronized boolean offer(byte[] source) {
      if (closedByReader) return true;
      if (done || source.length > buffer.length - used) return false;
      for (byte b : source) {
        buffer[(first + used) % buffer.length] = b;
        used++;
      }
      notifyAll();
      return true;
    }
    synchronized void finish(boolean discard) {
      if (discard) {
        // A revoked or locally closed stream may hold a token-bearing READY line.
        Arrays.fill(buffer, (byte) 0);
        used = 0; first = 0;
      }
      done = true;
      notifyAll();
    }
    @Override public synchronized int available() { return used; }
    @Override public int read() throws IOException {
      byte[] one = new byte[1];
      int n = read(one, 0, 1);
      return n < 0 ? -1 : one[0] & 255;
    }
    @Override public synchronized int read(byte[] out, int off, int len)
        throws IOException {
      if (out == null) throw new NullPointerException();
      if (off < 0 || len < 0 || off > out.length - len)
        throw new IndexOutOfBoundsException();
      if (len == 0) return 0;
      while (used == 0 && !done) {
        try { wait(); }
        catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
          InterruptedIOException x = new InterruptedIOException("stream interrupted");
          x.initCause(interrupted);
          throw x;
        }
      }
      if (used == 0) return -1;
      int amount = Math.min(used, len);
      for (int i = 0; i < amount; i++) {
        int slot = (first+i)%buffer.length;
        out[off+i] = buffer[slot];
        buffer[slot] = 0; // Erase consumed bytes, preserve stream ordering.
      }
      first = (first+amount)%buffer.length;
      used -= amount;
      return amount;
    }
    @Override public synchronized void close() {
      closedByReader = true;
      finish(true);
    }
  }
}
