package com.dsh.android.p187;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
public final class P187LoopbackCapabilityTest {
  private static int checks;
  private static void check(boolean pass,String label){ checks++; if(!pass)throw new AssertionError(label);}
  public static void main(String[] unused)throws Exception {
    check(!P187LoopbackCapability.isValidStatus(null),"null");
    check(!P187LoopbackCapability.isValidStatus(""),"empty");
    check(!P187LoopbackCapability.isValidStatus("PASS;secret"),"no_embedded_payload");
    check(!P187LoopbackCapability.isValidStatus("CONNECT_http://example.org"),"no_external_url");
    check(!P187LoopbackCapability.isValidStatus("PASS/0.0.0.0"),"no_wildcard_claim");
    check(P187LoopbackCapability.isValidStatus("BIND_EACCES"),"denied_bound");
    check(P187LoopbackCapability.isValidStatus("CONNECT_EPERM"),"denied_connect");
    check(P187LoopbackCapability.isValidStatus("ACCEPT_TIMEOUT"),"accept_timeout");
    check(P187LoopbackCapability.isValidStatus("ECHO_OTHER"),"echo_error");
    check("CONNECT_OTHER".equals(P187LoopbackCapability.connect(-1,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),"invalid_port");
    check("CONNECT_OTHER".equals(P187LoopbackCapability.connect(187,"wrong")),"invalid_nonce");
    String result=P187LoopbackCapability.probeSelf();
    check(P187LoopbackCapability.isValidStatus(result),"bounded_probe_result");
    AtomicInteger completed=new AtomicInteger();
    CountDownLatch go=new CountDownLatch(1);Thread[] jobs=new Thread[4];
    for(int i=0;i<jobs.length;i++){
      jobs[i]=new Thread(()->{try{go.await();
        if(P187LoopbackCapability.isValidStatus(P187LoopbackCapability.probeSelf()))
          completed.incrementAndGet();
      }catch(InterruptedException interrupted){Thread.currentThread().interrupt();}});
      jobs[i].start();
    }
    go.countDown();for(Thread job:jobs)job.join(5000);
    check(completed.get()==4,"four_bounded_one_shots");
    // In a JVM, this uses a single UID, so this is NOT Android cross-UID proof.
    try(P187LoopbackCapability.Listener server=P187LoopbackCapability.bind()){
      AtomicReference<String> s=new AtomicReference<>();
      Thread responder=new Thread(()->s.set(server.acceptOnce()));responder.start();
      check("PASS".equals(P187LoopbackCapability.connect(server.port(),server.nonceHex())),"tcp_nonce_client");
      responder.join(2500);
      check("PASS".equals(s.get()),"tcp_nonce_server");
      check("ACCEPT_OTHER".equals(server.acceptOnce()),"one_shot_accept");
    }
    System.out.println("P187_LOOPBACK_JAVA8_SAFETY_TEST=PASS checks="+checks);
    System.out.println("P187_LOCAL_JVM_LOOPBACK_STATUS="+result);
    System.out.println("P187_ANDROID_ISOLATED_UID_RESULT=NOT_TESTED");
    System.out.println("P187_ORIGINAL_ENGINEMANAGER_HTTP_READY=NOT_TESTED");
  }
}
