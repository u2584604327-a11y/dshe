package com.dsh.android.p195;

import com.dsh.android.p194.P194OriginalModeSeal;
import com.dsh.p37.P37RemoteProcess;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Java8 only, fixed synthetic frames, NEVER real original EngineManager. */
public final class P195OriginalCoroutineLifecycleTest {
  private static final String SESSION="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static final int UID=99055;
  private static int checks;
  private static void yes(boolean b,String label){
    checks++;if(!b)throw new AssertionError("P195_"+label);
  }
  private interface Run {void go()throws Exception;}
  private static void denied(String expected,Run r)throws Exception {
    try{r.go();throw new AssertionError("P195_UNEXPECTED_ACCEPT_"+expected);}
    catch(IOException x){yes(expected.equals(x.getMessage()),"DENY_"+expected);}
  }
  private static ProcessBuilder builder(int mode){
    return new ProcessBuilder("/p195/NEVER_EXECUTE","--test-only")
       .directory(new File("/"))
       .redirectErrorStream(mode!=P194OriginalModeSeal.RUN_DUMP_CONFIG);
  }
  private static class Port implements P37RemoteProcess.RemoteControl {
    int stopped,killed;
    public void requestGracefulStop(){stopped++;}
    public void requestForceStop(){killed++;}
  }
  private static P37RemoteProcess proxy(int mode,Port port){
    return new P37RemoteProcess(UID,SESSION,u->u==UID,port,
        mode!=P194OriginalModeSeal.RUN_DUMP_CONFIG);
  }
  private static P195OriginalCoroutineLifecycle attach(
      P37RemoteProcess p,int mode,long epoch)throws Exception {
    ProcessBuilder b=builder(mode);
    P194OriginalModeSeal seal=P194OriginalModeSeal.capture(b,mode,SESSION,epoch,1);
    P195OriginalCoroutineLifecycle x=
        P195OriginalCoroutineLifecycle.observeAfterReturnedProcess(
            seal,b,mode,SESSION,epoch,1,p);
    yes(seal.isTerminal(),"P194_PRELAUNCH_CONSUMED");
    yes(x.retainsExactProcess(p),"P37_EXACT_ALIAS");
    yes(x.observedOriginalMode()==mode,"EXACT_MODE");
    yes(!x.hasProductionEngineReady(),"INITIAL_NO_READY");
    return x;
  }
  private static final class Reader {
    final CountDownLatch ready=new CountDownLatch(1);
    final CountDownLatch go=new CountDownLatch(1);
    final AtomicReference<Throwable> failure=new AtomicReference<>();
    final ByteArrayOutputStream buffer=new ByteArrayOutputStream();
    final Thread thread;
    Reader(P37RemoteProcess p,P195OriginalCoroutineLifecycle lifecycle,boolean malformedEof){
      thread=new Thread(()->{
        ready.countDown();
        try {
          if(!go.await(3,TimeUnit.SECONDS))
            throw new AssertionError("P195_READER_GATE_TIMEOUT");
          InputStream stream=p.getInputStream();
          byte[] tmp=new byte[64];
          int n;
          while((n=stream.read(tmp))!=-1)buffer.write(tmp,0,n);
          lifecycle.observeReaderEOF(malformedEof?0:n);
        }catch(Throwable e){failure.set(e);}
      },"p195-fixed-original-reader-fixture");
      thread.setDaemon(true);
    }
    void start()throws Exception {
      thread.start();
      yes(ready.await(2,TimeUnit.SECONDS),"READER_THREAD_STARTED");
      yes(thread.isAlive(),"READER_ALIVE");
    }
    void release() {go.countDown();}
    void join()throws Exception {
      thread.join(2500);
      yes(!thread.isAlive(),"READER_BOUNDED_EXIT");
    }
    String text(){return new String(buffer.toByteArray(),StandardCharsets.US_ASCII);}
  }
  private static void success(int mode,boolean rapidExit)throws Exception {
    Port stop=new Port();
    P37RemoteProcess p=proxy(mode,stop);
    String msg="P195_NOT_REAL_NODE_READY\n";
    byte[] fake=msg.getBytes(StandardCharsets.US_ASCII);
    yes(p.onAuthenticatedStdout(UID,SESSION,fake),"FIXTURE_STDOUT_PRE_EXIT");
    if(mode!=2)yes(p.onAuthenticatedStderr(UID,SESSION,
            "merged-test-only\n".getBytes(StandardCharsets.US_ASCII)),
            "MERGED_FRAME");
    if(rapidExit)yes(p.onAuthenticatedExit(UID,SESSION,0),"EARLY_CLEAN_EXIT");
    P195OriginalCoroutineLifecycle x=attach(p,mode,rapidExit?1000+mode:2000+mode);
    x.observeProcessFieldAssignment(p);
    Reader r=new Reader(p,x,false);
    r.start();
    x.observeReaderThreadStarted(r.thread);
    x.observeLatchAwait();
    yes(!x.hasProductionEngineReady(),"UNTRUSTED_LOG_TEXT_NOT_READY");
    r.release();
    if(!rapidExit)yes(p.onAuthenticatedExit(UID,SESSION,0),"CLEAN_EXIT");
    r.join();
    yes(r.failure.get()==null,"READER_EOF_OBSERVED_"+r.failure.get());
    String expected=msg+(mode==2?"":"merged-test-only\n");
    yes(expected.equals(r.text()),"ORIGINAL_MERGED_OR_SPLIT_READER_ORDER");
    if(mode==2) {
      byte[] b=new byte[8];
      yes(p.getErrorStream().read(b)==-1,"CONFIG_STDERR_UNTOUCHED_EOF");
    }else yes(p.getErrorStream().read()==-1,"MERGED_STDERR_EMPTY");
    x.observeAuthenticatedExit();
    yes(x.isComplete(),"SEQUENCE_FULLY_OBSERVED");
    yes(!x.hasProductionEngineReady(),"COMPLETE_IS_NOT_READY");
    yes(p.waitFor()==0 && stop.killed==0,"REAL_CLEAN_EXIT_NO_SYNTHETIC_KILL");
    x.close();
    yes(x.hasFailed(),"CLOSE_REVOKES_FURTHER_SOURCE_OBSERVATIONS");
  }
  private static void caseWrongProcess()throws Exception {
    P37RemoteProcess p=proxy(3,new Port());
    P37RemoteProcess other=proxy(3,new Port());
    P195OriginalCoroutineLifecycle x=attach(p,3,52);
    denied("P195_DIFFERENT_PROCESS_OBJECT",()->x.observeProcessFieldAssignment(other));
    yes(x.hasFailed(),"MISMATCH_REVOKES");
    denied("P195_PROCESS_FIELD_ORDER_OR_REPLAY",()->x.observeProcessFieldAssignment(p));
    p.onTransportLost();other.onTransportLost();
  }
  private static void caseOrdering()throws Exception {
    P37RemoteProcess p=proxy(3,new Port());
    P195OriginalCoroutineLifecycle x=attach(p,3,53);
    denied("P195_LATCH_BEFORE_READER_DENIED",x::observeLatchAwait);
    yes(x.hasFailed(),"BAD_ORDER_BURNS");
    p.onTransportLost();

    P37RemoteProcess q=proxy(3,new Port());
    P195OriginalCoroutineLifecycle y=attach(q,3,54);
    y.observeProcessFieldAssignment(q);
    denied("P195_READER_NOT_STARTED_OR_INVALID",
        ()->y.observeReaderThreadStarted(Thread.currentThread()));
    yes(y.hasFailed(),"NOT_STARTED_READER_REVOKES");
    q.onTransportLost();
  }
  private static void caseReportedNotEOF()throws Exception {
    P37RemoteProcess p=proxy(3,new Port());
    P195OriginalCoroutineLifecycle x=attach(p,3,61);
    x.observeProcessFieldAssignment(p);
    Reader r=new Reader(p,x,true);
    r.start();
    x.observeReaderThreadStarted(r.thread);
    x.observeLatchAwait();
    r.release();
    yes(p.onAuthenticatedExit(UID,SESSION,0),"END_FOR_BAD_EOF");
    r.join();
    yes(r.failure.get() instanceof IOException,"BAD_EOF_DENIED");
    yes("P195_EOF_NOT_FROM_AUTHENTIC_READER_RESULT".equals(
       r.failure.get().getMessage()),"EOF_EXACT_REASON");
    yes(x.hasFailed(),"FALSE_EOF_REVOKES");
  }
  private static void caseTransportLoss()throws Exception {
    Port stop=new Port();
    P37RemoteProcess p=proxy(2,stop);
    P195OriginalCoroutineLifecycle x=attach(p,2,70);
    x.observeProcessFieldAssignment(p);
    Reader r=new Reader(p,x,false);
    r.start();
    x.observeReaderThreadStarted(r.thread);
    x.observeLatchAwait();
    r.release();
    p.onTransportLost();
    r.join();
    yes(r.failure.get() instanceof IOException,"DISCONNECT_DENIED");
    yes("P195_REMOTE_TRANSPORT_OR_CHILD_FAILED".equals(
        r.failure.get().getMessage()),"TRANSPORT_EXACT_REASON");
    yes(x.hasFailed() && !x.hasProductionEngineReady(),
        "DISCONNECT_NEVER_READY");
    yes(p.waitFor()==125 && stop.killed==1,"FAIL_CLOSED_REMOTE_KILL");
  }
  private static void casePrematureExitObservation()throws Exception {
    P37RemoteProcess p=proxy(3,new Port());
    P195OriginalCoroutineLifecycle x=attach(p,3,72);
    x.observeProcessFieldAssignment(p);
    Reader r=new Reader(p,x,false);
    r.start();
    x.observeReaderThreadStarted(r.thread);
    x.observeLatchAwait();
    denied("P195_EXIT_BEFORE_READER_EOF",x::observeAuthenticatedExit);
    yes(x.hasFailed(),"EARLY_EXIT_OBSERVATION_REVOKED");
    r.release();p.onAuthenticatedExit(UID,SESSION,0);r.join();
  }
  private static void caseInvalidSealOrChild()throws Exception {
    P37RemoteProcess p=proxy(3,new Port());
    ProcessBuilder b=builder(3);
    P194OriginalModeSeal seal=P194OriginalModeSeal.capture(b,3,SESSION,91,1);
    denied("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",
      ()->P195OriginalCoroutineLifecycle.observeAfterReturnedProcess(
        seal,b,2,SESSION,91,1,p));
    yes(seal.isTerminal(),"MISMATCH_BURNED");
    denied("P194_ALREADY_CONSUMED_OR_REVOKED",
      ()->P195OriginalCoroutineLifecycle.observeAfterReturnedProcess(
        seal,b,3,SESSION,91,1,p));
    P194OriginalModeSeal good=P194OriginalModeSeal.capture(b,3,SESSION,92,1);
    denied("P195_NO_VERIFIED_P37_PROCESS",
      ()->P195OriginalCoroutineLifecycle.observeAfterReturnedProcess(
        good,b,3,SESSION,92,1,null));
    yes(good.isTerminal(),"NULL_CHILD_BURNS_SEAL");
    p.onTransportLost();
    P194OriginalModeSeal lost=P194OriginalModeSeal.capture(b,3,SESSION,93,1);
    denied("P195_UNTRUSTED_OR_LOST_CHILD",
      ()->P195OriginalCoroutineLifecycle.observeAfterReturnedProcess(
        lost,b,3,SESSION,93,1,p));
    yes(lost.isTerminal(),"LOST_CHILD_BURNS_SEAL");
  }
  public static void main(String[] args)throws Exception {
    success(1,false);
    success(2,false);
    success(3,false);
    success(3,true);
    caseWrongProcess();
    caseOrdering();
    caseReportedNotEOF();
    caseTransportLoss();
    casePrematureExitObservation();
    caseInvalidSealOrChild();
    System.out.println("P195_PROCESS_ALIAS_P194_SEAL_READER_LATCH_AND_AUTH_EXIT=PASS");
    System.out.println("P195_THREE_MODES_REAL_P37_STREAM_READER_EOF=PASS");
    System.out.println("P195_STALE_EOF_TRANSPORT_LOSS_AND_FAKE_READY_DENIED=PASS");
    System.out.println("P195_JAVA8_ORIGINAL_LIFECYCLE_FIXTURE=PASS checks="+checks);
    System.out.println("P195_TRUE_ENGINE_MANAGER_COROUTINE=NOT_WIRED");
    System.out.println("P195_REAL_NODE_TOKEN_HTTP_READY=NOT_WIRED");
  }
}
