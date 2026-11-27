package com.dsh.android.p193;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * P193 TEST-ONLY host-owned 127.0.0.1 listener and simulated Binder frame gate.
 * NO Android Messenger is wired. The supplied UID is NOT authenticated here:
 * only a future Android Handler may supply Message.sendingUid, after verifying
 * the actual host/worker identity. No production Node or original HTTP READY.
 * This code must NOT be used as an app's general-purpose HTTP proxy.
 */
public final class P193HostLoopbackFixture implements AutoCloseable {
  public static final int MAX_HEADER_BYTES = 1024;
  public static final int MAX_REPLY_BYTES = 32;
  public static final int MAX_PENDING_REQUESTS = 1;
  private static final int DEADLINE_MS = 1500;
  private static final String BODY = "P193_FIXTURE_OK";
  private static final byte[] EXPECTED_REPLY = BODY.getBytes(StandardCharsets.US_ASCII);
  private static final InetAddress LOCAL = ipv4Loopback();

  public interface SimulatedBinderPort {
    // Test harness only; not an Android Messenger, Binder or trusted native port.
    void dispatch(Frame frame) throws Exception;
  }

  public static final class Frame {
    public final String command = "GET_FIXED_OFFLINE_FIXTURE";
    public final String hostSession;
    public final String assetDigest;
    public final long ownerEpoch;
    public final String nonce;
    public final int sequence = 1;
    private Frame(String session, String digest, long epoch, String nonce) {
      this.hostSession=session;
      this.assetDigest=digest;
      this.ownerEpoch=epoch;
      this.nonce=nonce;
    }
  }

  private final String session;
  private final String digest;
  private final int isolatedUid;
  private final long epoch;
  private final String token;
  private final String nonce;
  private final SimulatedBinderPort binder;
  private final ServerSocket server;
  private final Object lock = new Object();
  private boolean served;
  private boolean inFlight;
  private boolean completed;
  private boolean revoked;

  private static InetAddress ipv4Loopback() {
    try { return InetAddress.getByAddress(new byte[]{127,0,0,1}); }
    catch (IOException impossible) { throw new AssertionError(impossible); }
  }
  private static String freshHex() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    char[] chars=new char[bytes.length*2];
    char[] hex="0123456789abcdef".toCharArray();
    for(int i=0;i<bytes.length;i++){
      chars[2*i]=hex[(bytes[i]&255)>>>4];
      chars[2*i+1]=hex[bytes[i]&15];
    }
    return new String(chars);
  }

  public P193HostLoopbackFixture(String hostGeneratedSession, String pinnedAssetDigest,
                                 long ownerEpoch, int expectedIsolatedUid,
                                 SimulatedBinderPort simulatedPort) throws IOException {
    if(hostGeneratedSession==null || !hostGeneratedSession.matches("[a-f0-9]{64}") ||
       pinnedAssetDigest==null || !pinnedAssetDigest.matches("[a-f0-9]{64}") ||
       ownerEpoch<=0 || expectedIsolatedUid<=0 || simulatedPort==null)
      throw new IllegalArgumentException("P193_BOUNDED_TEST_INPUT_REQUIRED");
    session=hostGeneratedSession;
    digest=pinnedAssetDigest;
    epoch=ownerEpoch;
    isolatedUid=expectedIsolatedUid;
    binder=simulatedPort;
    token=freshHex();
    nonce=freshHex();
    ServerSocket candidate=new ServerSocket();
    try {
      candidate.setReuseAddress(false);
      candidate.setSoTimeout(DEADLINE_MS);
      candidate.bind(new InetSocketAddress(LOCAL,0),1);
      if(!LOCAL.equals(candidate.getInetAddress()) || candidate.getLocalPort()<=0)
        throw new SecurityException("P193_LOOPBACK_ONLY");
      server=candidate;
    }catch(IOException | RuntimeException failure){
      try{candidate.close();}catch(IOException ignored){}
      throw failure;
    }
  }
  public int localhostPort(){return server.getLocalPort();}
  /** Fixture client credential; never persist, print or expose in production. */
  public String fixtureTokenForTest(){return token;}
  public boolean isBoundOnlyToIPv4Loopback(){return LOCAL.equals(server.getInetAddress());}

  /**
   * Must only be called by a future REAL Android Messenger Handler with
   * framework-provided Message.sendingUid. Until then, a FAKE Binder callback
   * exercises the state machine but does not certify platform identity.
   * Any invalid callback while in flight permanently fails this one-shot lease.
   */
  public boolean receiveSimulatedFrameworkReply(int frameworkUid, String hostSession,
      String pinnedDigest, long ownerEpoch, String responseNonce,
      int sequence, byte[] payload) {
    synchronized(lock){
      if(revoked || !inFlight || completed) return false;
      if(frameworkUid!=isolatedUid || !session.equals(hostSession) ||
         !digest.equals(pinnedDigest) || epoch!=ownerEpoch ||
         !nonce.equals(responseNonce) || sequence!=1 || payload==null ||
         payload.length<1 || payload.length>MAX_REPLY_BYTES ||
         !Arrays.equals(EXPECTED_REPLY,payload)) {
        revoked=true;
        lock.notifyAll();
        return false;
      }
      completed=true;
      lock.notifyAll();
      return true;
    }
  }

  private static byte[] receiveHeader(Socket peer) throws IOException {
    InputStream in=peer.getInputStream();
    ByteArrayOutputStream b=new ByteArrayOutputStream();
    int a=0,z=0,y=0,x=0;
    while(b.size()<MAX_HEADER_BYTES){
      int n=in.read();
      if(n<0)break;
      if(n==0 || n>127)throw new IOException("P193_NON_ASCII_HTTP_REJECTED");
      b.write(n);
      x=y; y=z; z=a; a=n;
      if(x==13 && y==10 && z==13 && a==10)return b.toByteArray();
    }
    throw new IOException("P193_HEADER_MISSING_OR_OVERFLOW");
  }

  private boolean exactRequest(byte[] bytes) {
    String s=new String(bytes,StandardCharsets.US_ASCII);
    String expected="GET /p193/fixture HTTP/1.1\r\n"+
                    "Host: 127.0.0.1\r\n"+
                    "Authorization: Bearer "+token+"\r\n"+
                    "Connection: close\r\n\r\n";
    // No other method, path, host, header, cookies, body or upload accepted.
    // Compare entire canonical request, avoiding parser differential behavior.
    return expected.equals(s);
  }

  private static void respond(OutputStream out, int code) throws IOException {
    String status=code==200?"200 OK":code==403?"403 Forbidden":"503 Service Unavailable";
    byte[] body=code==200?EXPECTED_REPLY:new byte[0];
    String headers="HTTP/1.1 "+status+"\r\n"+
        "Content-Type: text/plain; charset=us-ascii\r\n"+
        "Cache-Control: no-store\r\n"+
        "Content-Length: "+body.length+"\r\n"+
        "Connection: close\r\n\r\n";
    out.write(headers.getBytes(StandardCharsets.US_ASCII));
    out.write(body);
    out.flush();
  }

  /** Single client only; call on disposable test worker thread, never Android UI. */
  public void serveOneClient() throws IOException {
    synchronized(lock){
      if(served || revoked)throw new IllegalStateException("P193_SINGLE_USE_OR_REVOKED");
      served=true;
    }
    try(Socket peer=server.accept()){
      peer.setSoTimeout(DEADLINE_MS);
      if(!LOCAL.equals(peer.getInetAddress())){
        respond(peer.getOutputStream(),403);
        return;
      }
      final boolean valid;
      try{valid=exactRequest(receiveHeader(peer));}
      catch(IOException badRequest){respond(peer.getOutputStream(),403);return;}
      if(!valid){respond(peer.getOutputStream(),403);return;}
      // Fixture protocol requires a client half-close to prove no body or
      // pipelined bytes; it is intentionally NOT a generic HTTP/1.1 server.
      // A missing half-close times out and denies rather than dispatching.
      peer.setSoTimeout(250);
      try {
        if(peer.getInputStream().read()!=-1){
          respond(peer.getOutputStream(),403);return;
        }
      }catch(SocketTimeoutException unprovenBoundary){
        respond(peer.getOutputStream(),403);return;
      }
      synchronized(lock){
        if(revoked){respond(peer.getOutputStream(),503);return;}
        inFlight=true;
      }
      try{binder.dispatch(new Frame(session,digest,epoch,nonce));}
      catch(Exception rejected){
        synchronized(lock){revoked=true;lock.notifyAll();}
      }
      boolean passed;
      synchronized(lock){
        long deadline=System.nanoTime()+DEADLINE_MS*1000000L;
        while(!completed && !revoked){
          long rem=deadline-System.nanoTime();
          if(rem<=0){revoked=true;break;}
          try {lock.wait(Math.max(1L,rem/1000000L));}
          catch(InterruptedException cancelled){
            Thread.currentThread().interrupt();revoked=true;break;
          }
        }
        passed=completed&&!revoked;
        inFlight=false;
      }
      respond(peer.getOutputStream(),passed?200:503);
    }catch(SocketTimeoutException noClient){
      synchronized(lock){revoked=true;lock.notifyAll();}
      throw noClient;
    }finally{
      close();
    }
  }

  @Override public void close(){
    synchronized(lock){revoked=true;lock.notifyAll();}
    try{server.close();}catch(IOException ignored){}
  }
}
