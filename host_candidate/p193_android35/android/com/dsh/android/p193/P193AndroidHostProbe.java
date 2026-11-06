package com.dsh.android.p193;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * P193 Android35 TEMPORARY original-package APK test hook only.
 * The normal host UID owns loopback. Isolated UID NEVER gets a socket.
 * Only real Message.sendingUid from this app's Messenger handler is passed
 * to the Java8 protocol state. Not a production broker or Node endpoint.
 */
public final class P193AndroidHostProbe implements AutoCloseable {
  public static final int REQUEST=1931, REPLY=1932;
  public interface Reporter { void report(String safeStatus); }
  private final Messenger isolated;
  private final String session, assetDigest;
  private final int isolatedUid;
  private final Reporter reporter;
  private final Handler main=new Handler(Looper.getMainLooper());
  private volatile P193HostLoopbackFixture fixture;
  private volatile boolean closed, accepted, duplicateDenied, finished;
  // A valid HTTP 200 can reach the client before the Android main Looper
  // handles the intentional second Binder callback. Do not mistake that
  // scheduling race for a bypass or silently ignore the replay.
  private final CountDownLatch realReplayChecked=new CountDownLatch(1);
  private Thread runner;

  public P193AndroidHostProbe(Messenger boundWorker, String hostSession,
      String sha256, int frameworkIsolatedUid, Reporter output) {
    if(boundWorker==null || output==null || hostSession==null ||
       !hostSession.matches("[a-f0-9]{64}") || sha256==null ||
       !sha256.matches("[a-f0-9]{64}") || frameworkIsolatedUid<=0 ||
       frameworkIsolatedUid==android.os.Process.myUid() ||
       !android.os.Process.isIsolatedUid(frameworkIsolatedUid))
      throw new IllegalArgumentException("P193_REAL_BINDER_HOST_PRECONDITION");
    isolated=boundWorker; session=hostSession; assetDigest=sha256;
    isolatedUid=frameworkIsolatedUid; reporter=output;
  }
  private void report(String safe) {
    if(!closed)main.post(()->{if(!closed)reporter.report(safe);});
  }
  private void send(P193HostLoopbackFixture.Frame frame, boolean invalidSession)
      throws RemoteException {
    Message m=Message.obtain(null,REQUEST);
    Bundle b=new Bundle();
    String s=frame.hostSession;
    if(invalidSession)s=(s.charAt(0)=='a'?"b":"a")+s.substring(1);
    b.putString("session",s);
    b.putString("digest",frame.assetDigest);
    b.putLong("epoch",frame.ownerEpoch);
    b.putString("nonce",frame.nonce);
    b.putInt("seq",frame.sequence);
    b.putString("cmd",frame.command);
    m.setData(b);
    // No replyTo is necessary: the worker uses the already authenticated
    // P43 INIT Messenger and returns to the same host reply endpoint.
    // DO NOT send a URL, hostname, cookie, token or filesystem capability.
    isolated.send(m);
  }

  public void start() {
    if(runner!=null)throw new IllegalStateException("P193_STARTED_TWICE");
    runner=new Thread(()->{
      P193HostLoopbackFixture f=null;
      try {
        final long epoch=1; // disposable single-use Activity epoch only
        f=new P193HostLoopbackFixture(session,assetDigest,epoch,isolatedUid,
            frame->{
              // First genuinely wrong-session host-to-isolated Binder frame;
              // worker MUST reject it without consuming its one-shot permit.
              send(frame,true);
              send(frame,false);
            });
        fixture=f;
        final P193HostLoopbackFixture live=f;
        Thread serve=new Thread(()->{
          try { live.serveOneClient(); }
          catch(IOException | RuntimeException failed){
            report("P193_ANDROID35_LOOPBACK_SERVER_ERROR=DENY");
          }
        },"p193-host-local-serve");
        serve.start();
        String http=roundTrip(f.localhostPort(),f.fixtureTokenForTest());
        serve.join(4000);
        if(serve.isAlive()) {
          f.close();serve.interrupt();
          report("P193_ANDROID35_LOOPBACK_SERVER_TIMEOUT=DENY");
          return;
        }
        // A valid first reply releases the host socket before the second
        // same-worker Binder callback is necessarily dispatched on main.
        // Observe an actual schema+UID-checked replay within a bounded time;
        // never infer replay denial from HTTP success or wait unboundedly.
        boolean httpStatusOk=http.startsWith("HTTP/1.1 200 OK\r\n");
        // HTTP 200 may become visible before the Binder main-Looper
        // callback publishes the volatile accepted flag. Await the genuine
        // replay latch even if accepted has not yet been published; the
        // latch is counted down ONLY after the real UID/schema-checked
        // second callback is rejected. Keep the original 1500ms deadline.
        boolean replayObserved=httpStatusOk &&
            realReplayChecked.await(1500,TimeUnit.MILLISECONDS);
        boolean httpBodyOk=http.endsWith("P193_FIXTURE_OK");
        if(!closed && replayObserved && duplicateDenied && httpBodyOk) {
          report("P193_ANDROID35_HOST_LOOPBACK_BINDER_TWO_UID=PASS");
          report("P193_ANDROID35_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED");
        }else{
          // Category-only failure classification. Do not log HTTP bytes,
          // token, Binder payload, UID, nonce, session or a stack trace.
          // All existing timeouts, network/UID/session guards stay unchanged.
          if(!httpStatusOk)report("P193_ANDROID35_HTTP_STATUS_MISMATCH=DENY");
          if(!httpBodyOk)report("P193_ANDROID35_HTTP_BODY_MISMATCH=DENY");
          if(!accepted)report("P193_ANDROID35_BINDER_ACCEPT_MISSING=DENY");
          if(realReplayChecked.getCount()!=0)
            report("P193_ANDROID35_REPLAY_NOT_OBSERVED=DENY");
          if(!duplicateDenied)
            report("P193_ANDROID35_REPLAY_NOT_DENIED=DENY");
          report("P193_ANDROID35_LOOPBACK_OR_BINDER_VALIDATION=DENY");
        }
      }catch(Exception rejected) {
        report("P193_ANDROID35_FIXED_FIXTURE_ERROR=DENY");
      }finally {
        finished=true;
        if(f!=null)f.close();
      }
    },"p193-host-only-http-client");
    runner.start();
  }

  /** Invoked only from P43 original-package host Messenger callback. */
  public boolean onRealFrameworkMessage(Message m) {
    if(m==null || m.what!=REPLY)return false;
    P193HostLoopbackFixture f=fixture;
    if(closed || f==null || finished)return true; // late reply: deny
    // UID comes directly from the framework Message; NEVER Bundle data.
    if(m.sendingUid!=isolatedUid || !android.os.Process.isIsolatedUid(m.sendingUid) ||
       m.sendingUid==android.os.Process.myUid()) {
      f.close();
      report("P193_ANDROID35_FRAMEWORK_SENDER_UID=DENY");
      return true;
    }
    try {
      Bundle b=m.getData();
      if(b==null || b.keySet().size()!=6 ||
         !b.containsKey("session") || !b.containsKey("digest") ||
         !b.containsKey("epoch") || !b.containsKey("nonce") ||
         !b.containsKey("seq") || !b.containsKey("payload")) {
        f.close(); report("P193_ANDROID35_FRAME_SCHEMA=DENY");return true;
      }
      boolean pass=f.receiveSimulatedFrameworkReply(
          m.sendingUid,b.getString("session"),b.getString("digest"),
          b.getLong("epoch",-1),b.getString("nonce"),b.getInt("seq",-1),
          b.getByteArray("payload"));
      if(pass && !accepted) {
        accepted=true;
        report("P193_ANDROID35_FRAMEWORK_SENDING_UID_AUTH=PASS");
        return true;
      }
      if(!pass && accepted && !duplicateDenied) {
        duplicateDenied=true;
        realReplayChecked.countDown();
        report("P193_ANDROID35_BINDER_DUPLICATE_FRAME_REJECT=PASS");
        return true;
      }
      f.close();report("P193_ANDROID35_REPLAY_OR_FRAME=DENY");
    }catch(RuntimeException invalid) {
      f.close();report("P193_ANDROID35_MALFORMED_FRAME=DENY");
    }
    return true;
  }

  private static String roundTrip(int port,String token) throws IOException {
    final InetAddress v4=InetAddress.getByAddress(new byte[]{127,0,0,1});
    try(Socket socket=new Socket()){
      socket.connect(new InetSocketAddress(v4,port),1200);
      socket.setSoTimeout(2800);
      String get="GET /p193/fixture HTTP/1.1\r\n"+
          "Host: 127.0.0.1\r\nAuthorization: Bearer "+token+
          "\r\nConnection: close\r\n\r\n";
      socket.getOutputStream().write(get.getBytes(StandardCharsets.US_ASCII));
      socket.getOutputStream().flush();
      socket.shutdownOutput();
      ByteArrayOutputStream bytes=new ByteArrayOutputStream();
      InputStream in=socket.getInputStream();
      byte[] buffer=new byte[256];int n;
      while((n=in.read(buffer))>=0){
        if(n>2048-bytes.size())throw new IOException("P193_REPLY_BOUNDS");
        bytes.write(buffer,0,n);
      }
      return bytes.toString("US-ASCII");
    }
  }
  @Override public void close(){
    closed=true;
    P193HostLoopbackFixture f=fixture;
    if(f!=null)f.close();
  }
}
