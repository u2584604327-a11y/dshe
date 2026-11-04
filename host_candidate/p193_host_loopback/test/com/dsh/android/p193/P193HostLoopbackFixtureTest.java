package com.dsh.android.p193;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

/** Offline Java8 host-only loopback with simulated Binder (NO Android UIDs). */
public final class P193HostLoopbackFixtureTest {
  private static final String SESSION=repeat('a',64), DIGEST=repeat('b',64);
  private static final int UID=99001;
  private static final long EPOCH=21L;
  private static int checks;
  private static String repeat(char c,int n){char[] b=new char[n];Arrays.fill(b,c);return new String(b);}
  private static void verify(boolean ok,String name){if(!ok)throw new AssertionError(name);checks++;}
  private static byte[] ack(){return "P193_FIXTURE_OK".getBytes(StandardCharsets.US_ASCII);}
  private static String request(String token){
    return "GET /p193/fixture HTTP/1.1\r\nHost: 127.0.0.1\r\n"+
        "Authorization: Bearer "+token+"\r\nConnection: close\r\n\r\n";
  }
  private static String connect(int port,String req) throws Exception {
    try(Socket s=new Socket()) {
      s.connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),1000);
      s.setSoTimeout(2500);
      s.getOutputStream().write(req.getBytes(StandardCharsets.US_ASCII));
      s.getOutputStream().flush();
      s.shutdownOutput(); // test-only complete-request boundary; no body
      ByteArrayOutputStream b=new ByteArrayOutputStream();
      InputStream in=s.getInputStream();
      byte[] tmp=new byte[256];int n;
      while((n=in.read(tmp))!=-1){b.write(tmp,0,n);if(b.size()>2048)throw new AssertionError("response too long");}
      return b.toString("US-ASCII");
    }
  }
  private interface TestPort { void send(P193HostLoopbackFixture f,P193HostLoopbackFixture.Frame frame) throws Exception; }
  private static final class Case {
    final AtomicReference<P193HostLoopbackFixture> ref=new AtomicReference<>();
    final AtomicReference<Throwable> failure=new AtomicReference<>();
    final P193HostLoopbackFixture fixture;
    final Thread runner;
    Case(TestPort port) throws Exception {
      fixture=new P193HostLoopbackFixture(SESSION,DIGEST,EPOCH,UID,frame->port.send(ref.get(),frame));
      ref.set(fixture);
      runner=new Thread(()->{
        try{fixture.serveOneClient();}catch(Throwable t){failure.set(t);}
      },"p193-local-only");runner.start();
    }
    String perform(String req) throws Exception {
      String response=connect(fixture.localhostPort(),req);
      runner.join(2500);
      verify(!runner.isAlive(),"test server exited");
      verify(failure.get()==null,"test server did not throw: "+failure.get());
      return response;
    }
    void close() throws Exception {fixture.close();runner.join(2500);}
  }
  private static String full(Case c){return request(c.fixture.fixtureTokenForTest());}
  private static void scenario(int expected, String name, TestPort port, String mutate) throws Exception {
    Case c=new Case(port);
    try {
      String req=full(c);
      if("bad-token".equals(mutate))req=req.replace(c.fixture.fixtureTokenForTest(),repeat('0',64));
      if("post".equals(mutate))req=req.replace("GET /p193/fixture", "POST /p193/fixture");
      if("path".equals(mutate))req=req.replace("/p193/fixture", "/v1/models");
      if("cookie".equals(mutate))req=req.replace("Connection: close", "Cookie: sess=abc\r\nConnection: close");
      if("header-overflow".equals(mutate))req=req.replace("Connection: close", "X-Long: "+repeat('q',1500)+"\r\nConnection: close");
      if("body".equals(mutate))req+="extra";
      String response=c.perform(req);
      verify(response.startsWith("HTTP/1.1 "+expected+" "),name+" status="+response.split("\\r\\n")[0]);
      if(expected==200)verify(response.endsWith("P193_FIXTURE_OK"),name+" fixed reply");
      else verify(!response.contains("P193_FIXTURE_OK"),name+" must not expose success payload");
    } finally {c.close();}
  }
  public static void main(String[] args) throws Exception {
    TestPort valid=(f,x)->verify(f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"valid simulated Binder reply accepted");
    scenario(200,"valid fixed response",valid,null);
    scenario(403,"bad token",valid,"bad-token");
    scenario(403,"unsafe method",valid,"post");
    scenario(403,"unsafe endpoint",valid,"path");
    scenario(403,"cookie rejected",valid,"cookie");
    scenario(403,"oversized header",valid,"header-overflow");
    scenario(403,"body rejected",valid,"body");
    scenario(503,"wrong UID",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID+1,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"wrong UID denied"),null);
    scenario(503,"wrong session",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,repeat('c',64),DIGEST,EPOCH,x.nonce,1,ack()),"wrong session denied"),null);
    scenario(503,"wrong digest",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,repeat('c',64),EPOCH,x.nonce,1,ack()),"wrong digest denied"),null);
    scenario(503,"wrong epoch",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH-1,x.nonce,1,ack()),"stale epoch denied"),null);
    scenario(503,"wrong nonce",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,repeat('c',64),1,ack()),"nonce denied"),null);
    scenario(503,"wrong sequence",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,2,ack()),"sequence denied"),null);
    scenario(503,"oversized Binder frame",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,new byte[33]),"oversized reply denied"),null);
    scenario(503,"wrong fixed payload",(f,x)->verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,"HELLO".getBytes(StandardCharsets.US_ASCII)),"payload denied"),null);
    scenario(503,"no Binder response timeout",(f,x)->{},null);
    scenario(503,"Binder failure",(f,x)->{throw new IllegalStateException("synthetic failure");},null);
    scenario(503,"invalid then valid replay blocked",(f,x)->{
      verify(!f.receiveSimulatedFrameworkReply(UID+2,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"reject first");
      verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"no replay");
    },null);
    scenario(200,"valid twice accepts once",(f,x)->{
      verify(f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"first accepted");
      verify(!f.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,x.nonce,1,ack()),"duplicate rejected");
    },null);
    Case close=new Case((f,x)->{});
    try{
      verify(close.fixture.isBoundOnlyToIPv4Loopback(),"host bound IPv4 only");
      close.fixture.close();
      verify(!close.fixture.receiveSimulatedFrameworkReply(UID,SESSION,DIGEST,EPOCH,repeat('c',64),1,ack()),"closed broker rejects late reply");
    }finally{close.close();}
    boolean inputRejected=false;
    try{new P193HostLoopbackFixture("invalid",DIGEST,EPOCH,UID,f->{});}catch(IllegalArgumentException expected){inputRejected=true;}
    verify(inputRejected,"invalid trusted input denied");
    System.out.println("P193_HOST_IPV4_LOOPBACK_ONLY_AND_SINGLE_USE=PASS");
    System.out.println("P193_HTTP_FIXED_ENDPOINT_AUTH_AND_BOUNDS=PASS");
    System.out.println("P193_SIMULATED_BINDER_UID_SESSION_DIGEST_EPOCH_NONCE_REPLAY=PASS");
    System.out.println("P193_JAVA8_OFFLINE_TEST=PASS checks="+checks);
    System.out.println("P193_REAL_ANDROID_FRAMEWORK_UID=NOT_TESTED");
    System.out.println("P193_ORIGINAL_ENGINE_HTTP_TOKEN_READY=NOT_WIRED");
  }
}
