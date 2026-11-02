package com.dsh.p37;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** No Android stubs, APK, network, personal data or original DSH files. */
public final class P37RemoteProcessTest {
  private static final String S = new String(new char[64]).replace('\0','a');
  private static final int UID=99055;
  private static final AtomicInteger checks=new AtomicInteger();
  private static void ok(boolean b,String message) {
    checks.incrementAndGet();
    if (!b) throw new AssertionError(message);
  }
  private static class Port implements P37RemoteProcess.RemoteControl {
    int stop=0,kill=0;
    boolean failStop=false,failKill=false;
    @Override public void requestGracefulStop() {
      stop++;if(failStop)throw new IllegalStateException("lost");
    }
    @Override public void requestForceStop() {
      kill++;if(failKill)throw new IllegalStateException("lost");
    }
  }
  private static P37RemoteProcess start(Port p) {
    return new P37RemoteProcess(UID,S,uid->uid==UID,p);
  }
  private static byte[] b(String s) {return s.getBytes(StandardCharsets.UTF_8);}
  private static String readAll(InputStream input)throws Exception {
    ByteArrayOutputStream result=new ByteArrayOutputStream();
    byte[] tmp=new byte[200];int n;
    while((n=input.read(tmp))!=-1)result.write(tmp,0,n);
    return new String(result.toByteArray(),StandardCharsets.UTF_8);
  }
  private static void testLifecycle()throws Exception {
    Port port=new Port(); P37RemoteProcess p=start(port);
    ok(p.matchesBoundIdentity(UID,S),"same verified P37 bound identity");
    ok(!p.matchesBoundIdentity(UID+1,S),"wrong platform UID cannot match");
    ok(!p.matchesBoundIdentity(UID,S.replace('a','b')),"wrong session cannot match");
    ok(!p.matchesBoundIdentity(UID,null),"missing host session cannot match");
    ok(p.isAlive(),"alive at create");
    try {p.exitValue();throw new AssertionError("exitValue did not throw");}
    catch(IllegalThreadStateException expected){checks.incrementAndGet();}
    ok(!p.waitFor(0,TimeUnit.MILLISECONDS),"nonblocking wait should timeout");
    ExecutorService e=Executors.newSingleThreadExecutor();
    Future<String> reader=e.submit(()->readAll(p.getInputStream()));
    ok(p.onAuthenticatedStdout(UID,S,b("boot\n")),"stdout accepted");
    ok(p.onAuthenticatedStdout(UID,S,b("ready:1604\n")),"second chunk accepted");
    ok(p.onAuthenticatedStderr(UID,S,b("log\n")),"stderr accepted");
    p.destroy(); p.destroy();
    ok(port.stop==1,"stop idempotent");
    ok(p.isAlive(),"not exited until worker exit");
    ok(p.onAuthenticatedExit(UID,S,0),"verified exit");
    ok(!p.isAlive()&&p.exitValue()==0&&p.waitFor(1,TimeUnit.SECONDS),"clean exit");
    ok("boot\nready:1604\n".equals(reader.get(2,TimeUnit.SECONDS)),"ordered stdout and EOF");
    ok("log\n".equals(readAll(p.getErrorStream())),"separate stderr");
    ok(!p.onAuthenticatedExit(UID,S,17),"duplicate exit rejected");
    ok(p.waitFor()==0,"waitFor stable");
    e.shutdownNow();
  }
  private static void testIsolationAndReplay()throws Exception {
    Port port=new Port(); P37RemoteProcess p=start(port);
    ok(!p.onAuthenticatedStdout(10001,S,b("ready\n")),"fake UID rejected");
    ok(p.terminalReason()==P37RemoteProcess.TerminalReason.IDENTITY_MISMATCH,"identity terminal");
    ok(p.waitFor()==125 && port.kill==1,"kill requested and synthetic failure");
    ok(p.getInputStream().read()==-1,"bad payload discarded");
    ok(!p.onAuthenticatedStdout(UID,S,b("ready\n")),"no reuse after failure");
    Port port2=new Port();P37RemoteProcess q=start(port2);
    ok(!q.onAuthenticatedStderr(UID,S.substring(1),b("wrong")),"session denied");
    ok(port2.kill==1&&q.waitFor()==125,"session mismatch revokes");
  }
  private static void testBoundedBuffer()throws Exception {
    Port port=new Port();P37RemoteProcess p=start(port);
    byte[] chunk=new byte[P37RemoteProcess.MAX_FRAME_BYTES];
    Arrays.fill(chunk,(byte)'x');
    for(int i=0;i<16;i++)ok(p.onAuthenticatedStdout(UID,S,chunk),"buffer chunk " +i);
    ok(!p.onAuthenticatedStdout(UID,S,b("overflow")),"no unbounded queue");
    ok(p.terminalReason()==P37RemoteProcess.TerminalReason.BUFFER_OVERFLOW,"overflow reason");
    ok(port.kill==1&&p.waitFor()==125,"overflow kill request");
    ok(p.getInputStream().read()==-1,"overflow discards buffered secret/ready tokens");
    Port port2=new Port();P37RemoteProcess q=start(port2);
    ok(!q.onAuthenticatedStdout(UID,S,new byte[P37RemoteProcess.MAX_FRAME_BYTES+1]),"max chunk");
    ok(q.terminalReason()==P37RemoteProcess.TerminalReason.BUFFER_OVERFLOW,"oversize terminal");
  }
  private static void testTimeoutAndDisconnect()throws Exception {
    Port p1=new Port();P37RemoteProcess p=start(p1);
    ExecutorService e=Executors.newSingleThreadExecutor();
    Future<Integer> blocked=e.submit(()->p.getInputStream().read());
    p.onTransportLost();
    ok(blocked.get(2,TimeUnit.SECONDS)==-1,"stream interrupted on disconnect");
    ok(p.waitFor()==125 && p.terminalReason()==P37RemoteProcess.TerminalReason.TRANSPORT_LOST,"disconnect fail closed");
    ok(p1.kill==1,"kill requested on disconnect");
    e.shutdownNow();
    Port p2=new Port();P37RemoteProcess q=start(p2);
    q.destroyForcibly();q.destroyForcibly();
    ok(p2.kill==1 && q.isAlive(),"kill sent once, no fake ack");
    q.onStopDeadlineExpired();
    ok(q.waitFor()==125 && p2.kill==1,"deadline terminal");
  }
  private static void testStdinAndFailures()throws Exception {
    Port port=new Port();P37RemoteProcess p=start(port);
    try {p.getOutputStream().write(b("bad command"));throw new AssertionError("stdin open");}
    catch(IOException expected){checks.incrementAndGet();}
    port.failStop=true;
    p.destroy();
    ok(p.waitFor()==125,"control failure burns process");
    ok(p.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_CONTROL_FAILURE,"control failure state");
    Port invalid=new Port();
    try {new P37RemoteProcess(10000,S,uid->false,invalid);throw new AssertionError("wrong uid accepted");}
    catch(IllegalArgumentException expected){checks.incrementAndGet();}
  }
  private static void testLocalReaderCloseKeepsChildAlive()throws Exception {
    Port port=new Port();P37RemoteProcess p=start(port);
    p.getInputStream().close();
    ok(p.getInputStream().read()==-1,"closed stdout stays EOF");
    ok(p.onAuthenticatedStdout(UID,S,b("discard after close\\n")),
        "valid bounded stdout after reader close is discarded");
    ok(p.onAuthenticatedStderr(UID,S,b("still readable\\n")),
        "other stream remains live");
    ok(p.isAlive()&&port.kill==0,"reader close must not terminate child");
    ok(p.onAuthenticatedExit(UID,S,0)&&p.waitFor()==0,
        "actual child exit remains authoritative after reader close");
    ok("still readable\\n".equals(readAll(p.getErrorStream())),
        "stderr retained independently");

    Port mergedPort=new Port();
    P37RemoteProcess merged=new P37RemoteProcess(UID,S,uid->uid==UID,mergedPort,true);
    merged.getInputStream().close();
    ok(merged.onAuthenticatedStderr(UID,S,b("merged after close\\n")),
        "merged stderr follows closed stdout discard");
    ok(merged.getErrorStream().read()==-1,"merged error pipe stays EOF");
    ok(merged.isAlive()&&mergedPort.kill==0,
        "closing merged reader does not kill isolated child");
    ok(merged.onAuthenticatedExit(UID,S,0)&&merged.waitFor()==0,
        "merged child exit remains authentic");

    Port oversizedPort=new Port();P37RemoteProcess oversized=start(oversizedPort);
    oversized.getInputStream().close();
    ok(!oversized.onAuthenticatedStdout(UID,S,
        new byte[P37RemoteProcess.MAX_FRAME_BYTES+1]),
        "reader close cannot bypass frame-size cap");
    ok(oversized.waitFor()==125&&oversizedPort.kill==1&&
        oversized.terminalReason()==P37RemoteProcess.TerminalReason.BUFFER_OVERFLOW,
        "oversized frame still fails closed");

    Port spoofedPort=new Port();P37RemoteProcess spoofed=start(spoofedPort);
    spoofed.getInputStream().close();
    ok(!spoofed.onAuthenticatedStdout(UID+1,S,b("spoofed")),
        "reader close cannot bypass Binder identity");
    ok(spoofed.waitFor()==125&&spoofedPort.kill==1&&
        spoofed.terminalReason()==P37RemoteProcess.TerminalReason.IDENTITY_MISMATCH,
        "wrong UID still fails closed");
  }
  /** Synthetic token only; inspect private buffer without exposing its contents. */
  private static boolean bufferZeroized(InputStream stream)throws Exception {
    java.lang.reflect.Field f=stream.getClass().getDeclaredField("buffer");
    f.setAccessible(true);
    for(byte value:(byte[])f.get(stream))if(value!=0)return false;
    return true;
  }
  private static void testBufferedReadyTokenErasure()throws Exception {
    byte[] token=b("dsh web: http://127.0.0.1:3080/?token=synthetic-test-only\n");
    Port livePort=new Port();P37RemoteProcess live=start(livePort);
    ok(live.onAuthenticatedStdout(UID,S,token),"synthetic READY buffered");
    ok(!bufferZeroized(live.getInputStream()),"buffer positive control");
    byte[] read=new byte[token.length];
    ok(live.getInputStream().read(read)==token.length && Arrays.equals(read,token),
       "valid READY delivered intact");
    ok(bufferZeroized(live.getInputStream()),"consumed READY bytes zeroized");
    ok(live.isAlive()&&livePort.kill==0,"read zeroization cannot kill child");
    live.onAuthenticatedExit(UID,S,0);
    ok(live.waitFor()==0,"authentic exit after erasure");

    Port closePort=new Port();P37RemoteProcess closed=start(closePort);
    ok(closed.onAuthenticatedStdout(UID,S,token),"close fixture");
    ok(closed.getInputStream().read()==(token[0]&255),"partial read");
    closed.getInputStream().close();
    ok(bufferZeroized(closed.getInputStream()),"close zeroizes unread token");
    ok(closed.isAlive()&&closePort.kill==0,"local close cannot revoke child");
    closed.onAuthenticatedExit(UID,S,0);

    Port lostPort=new Port();P37RemoteProcess lost=start(lostPort);
    ok(lost.onAuthenticatedStdout(UID,S,token),"transport loss fixture");
    lost.onTransportLost();
    ok(bufferZeroized(lost.getInputStream()),"transport loss zeroizes token");
    ok(lost.waitFor()==125&&lostPort.kill==1,"transport loss still revokes");

    Port exitPort=new Port();P37RemoteProcess exited=start(exitPort);
    ok(exited.onAuthenticatedStdout(UID,S,token),"clean exit fixture");
    ok(exited.onAuthenticatedExit(UID,S,0),"clean exit authenticated");
    ok(!bufferZeroized(exited.getInputStream()),"clean exit preserves unread bytes");
    byte[] afterExit=new byte[token.length];
    ok(exited.getInputStream().read(afterExit)==token.length &&
       Arrays.equals(afterExit,token),"unread READY delivered after exit");
    ok(bufferZeroized(exited.getInputStream()),"post-exit read erases bytes");

    Port mergedPort=new Port();
    P37RemoteProcess merged=new P37RemoteProcess(UID,S,uid->uid==UID,mergedPort,true);
    ok(merged.onAuthenticatedStderr(UID,S,token),"merged stderr fixture");
    byte[] mergedRead=new byte[token.length];
    ok(merged.getInputStream().read(mergedRead)==token.length &&
       Arrays.equals(mergedRead,token),"merged stderr order preserved");
    ok(bufferZeroized(merged.getInputStream()),"merged stderr bytes zeroized");
    merged.onAuthenticatedExit(UID,S,0);
    System.out.println("P37_BUFFERED_TOKEN_BYTES_ZEROIZED_AFTER_READ_DISCARD=PASS");
  }

  /** Force frame enqueue to wait on the stream while EXIT tries to commit.
   * A terminal exit must never be published before an already admitted frame
   * is queued. The old implementation set REMOTE_EXIT while frame.offer()
   * was still blocked, and this deterministic schedule caught the inversion.
   */
  private static void awaitBlocked(Thread t, String label)throws Exception {
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
    while(t.getState()!=Thread.State.BLOCKED && System.nanoTime()<deadline) {
      if(!t.isAlive())throw new AssertionError(label+" ended unexpectedly");
      Thread.sleep(2);
    }
    ok(t.getState()==Thread.State.BLOCKED,label+" must reach bounded contention");
  }
  private static void testExitFrameAtomicity()throws Exception {
    Port port=new Port();P37RemoteProcess p=start(port);
    java.lang.reflect.Field f=P37RemoteProcess.class.getDeclaredField("stdout");
    f.setAccessible(true);
    Object stream=f.get(p);
    byte[] frame=b("synthetic-pre-exit-frame\\n");
    AtomicBoolean frameAccepted=new AtomicBoolean(false);
    AtomicBoolean exitAccepted=new AtomicBoolean(false);
    AtomicReference<Throwable> failure=new AtomicReference<>();
    Thread writer=new Thread(()->{
      try {frameAccepted.set(p.onAuthenticatedStdout(UID,S,frame));}
      catch(Throwable t){failure.compareAndSet(null,t);}
    },"p37-test-frame");
    Thread exiter=new Thread(()->{
      try {exitAccepted.set(p.onAuthenticatedExit(UID,S,0));}
      catch(Throwable t){failure.compareAndSet(null,t);}
    },"p37-test-exit");
    synchronized(stream) {
      writer.start();
      awaitBlocked(writer,"frame waiting for stream");
      exiter.start();
      awaitBlocked(exiter,"exit waiting for lifecycle lock");
      ok(p.terminalReason()==P37RemoteProcess.TerminalReason.RUNNING,
         "terminal exit must not overtake in-flight admitted frame");
    }
    writer.join(5000);exiter.join(5000);
    ok(!writer.isAlive()&&!exiter.isAlive(),"both callbacks terminate");
    ok(failure.get()==null,"callbacks do not throw");
    ok(frameAccepted.get()&&exitAccepted.get(),"frame accepted before exit");
    ok("synthetic-pre-exit-frame\\n".equals(readAll(p.getInputStream())),
       "pre-exit frame remains readable after authentic exit");
    ok(p.waitFor()==0&&port.kill==0,"clean exit without spurious child kill");
    ok(!p.onAuthenticatedStdout(UID,S,b("late")),
       "post-exit frame still rejected");
    System.out.println("P37_EXIT_FRAME_ORDER_SERIALIZED_WITH_TERMINAL=PASS");
  }
  public static void main(String[] args)throws Exception {
    testLifecycle();testIsolationAndReplay();testBoundedBuffer();
    testTimeoutAndDisconnect();testStdinAndFailures();
    testLocalReaderCloseKeepsChildAlive();
    testBufferedReadyTokenErasure();
    testExitFrameAtomicity();
    System.out.println("P37_JAVA_PROCESS_LIFECYCLE_PROXY_TESTS=PASS assertions="+checks);
    System.out.println("P37_ORIGINAL_ENGINEMANAGER_WIRING=NO");
    System.out.println("P37_ANDROID_BINDER_RUNTIME_E2E=NOT_TESTED");
    System.out.println("P37_V139_RELEASE=BLOCKED");
  }
}
