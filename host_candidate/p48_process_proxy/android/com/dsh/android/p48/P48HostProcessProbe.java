package com.dsh.android.p48;

import android.os.*;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * P48 true original DSH host-side authenticated Binder adapter to a Java
 * Process proxy. Never exposes a general start(command) interface.
 * Only a pre-authorized synthetic /system/bin/id -u fixture is executed.
 */
public final class P48HostProcessProbe {
  public interface Listener {
    void report(String status);
    void fail(String code);
  }
  private final Handler main=new Handler(Looper.getMainLooper());
  private final Messenger isolated;
  private final String session;
  private final Listener listener;
  private final boolean exactOriginalArm64Node;
  private final CountDownLatch readers=new CountDownLatch(2);
  private final AtomicReference<String> stdout=new AtomicReference<>("");
  private final AtomicReference<String> stderr=new AtomicReference<>("");
  private int workerUid=-1;
  private long expectedSequence=1;
  private P37RemoteProcess proxy;
  private boolean complete,failed,started;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()) {
    @Override public void handleMessage(Message m) {
      if(failed||complete)return;
      int sender=m.sendingUid;
      if(!android.os.Process.isIsolatedUid(sender) ||
         sender==android.os.Process.myUid() ||
         (workerUid!=-1&&sender!=workerUid)) {
        failClosed("P48_BINDER_SENDER_UID_NOT_ISOLATED");return;
      }
      Bundle b;
      try{b=m.getData();}catch(RuntimeException e){failClosed("P48_BAD_BUNDLE");return;}
      if(!session.equals(b.getString("session"))) {
        failClosed("P48_SESSION_MISMATCH");return;
      }
      if(m.what==P48FixedIsolatedChild.HELLO) {
        if(workerUid!=-1 || b.getLong("seq",-1)!=0){
          failClosed("P48_DUPLICATE_HELLO");return;
        }
        workerUid=sender;
        proxy=new P37RemoteProcess(workerUid,session,
            android.os.Process::isIsolatedUid,
            new P37RemoteProcess.RemoteControl(){
              @Override public void requestGracefulStop() {
                sendControl(P48FixedIsolatedChild.STOP);
              }
              @Override public void requestForceStop() {
                sendControl(P48FixedIsolatedChild.KILL);
              }
            });
        new Thread(()->collect(proxy.getInputStream(),stdout),
                   "p48-host-stdout").start();
        new Thread(()->collect(proxy.getErrorStream(),stderr),
                   "p48-host-stderr").start();
        listener.report("P48_ORIGINAL_APP_BOUND_P37_REMOTE_PROCESS=PASS");
        return;
      }
      if(proxy==null || workerUid!=sender ||
         b.getLong("seq",-1)!=expectedSequence++){
        failClosed("P48_FRAME_SEQUENCE_OR_PROXY_MISSING");return;
      }
      if(m.what==P48FixedIsolatedChild.STDOUT ||
         m.what==P48FixedIsolatedChild.STDERR) {
        byte[] payload=b.getByteArray("data");
        if(payload==null||payload.length<1||payload.length>128 ||
           !(m.what==P48FixedIsolatedChild.STDOUT
             ? proxy.onAuthenticatedStdout(sender,session,payload)
             : proxy.onAuthenticatedStderr(sender,session,payload))) {
          failClosed("P48_FRAME_REJECTED");return;
        }
      }else if(m.what==P48FixedIsolatedChild.EXIT){
        int exit=b.getInt("exitCode",125);
        if(!proxy.onAuthenticatedExit(sender,session,exit)){
          failClosed("P48_EXIT_REJECTED");return;
        }
        verifyAsync(exit);
      }else if(m.what==P48FixedIsolatedChild.FAIL) {
        failClosed("P48_WORKER_CHILD_DENIED_OR_FAILED");
      }else failClosed("P48_UNRECOGNIZED_MESSAGE");
    }
  });

  public P48HostProcessProbe(Messenger isolated,String session,Listener listener) {
    this(isolated,session,listener,false);
  }
  public P48HostProcessProbe(Messenger isolated,String session,
                             Listener listener,boolean exactOriginalArm64Node) {
    if(isolated==null||listener==null||session==null||
       !session.matches("[a-f0-9]{64}"))
      throw new IllegalArgumentException("P48_BAD_HOST_SESSION");
    this.isolated=isolated;
    this.session=session;
    this.listener=listener;
    this.exactOriginalArm64Node=exactOriginalArm64Node;
  }
  public void start() {
    if(started)throw new IllegalStateException("P48_ALREADY_STARTED");
    started=true;
    Message m=Message.obtain(null,P48FixedIsolatedChild.START);
    Bundle b=new Bundle();b.putString("session",session);
    b.putString("p50_mode",exactOriginalArm64Node?
        "p50-exact-original-node":"p48-fixed-id");
    m.setData(b);
    m.replyTo=inbox;
    try{isolated.send(m);}
    catch(Exception e){failClosed("P48_INIT_SEND_FAILED");return;}
    main.postDelayed(()->{
      if(!failed&&!complete)failClosed("P48_ISOLATED_CHILD_DEADLINE");
    },14000);
  }
  private void sendControl(int code){
    Message m=Message.obtain(null,code);
    Bundle b=new Bundle();b.putString("session",session);m.setData(b);
    try{isolated.send(m);}catch(Exception ignored){}
  }
  private void collect(InputStream input,AtomicReference<String> sink){
    try(InputStream stream=input; ByteArrayOutputStream out=new ByteArrayOutputStream()){
      byte[] buf=new byte[64];int n;
      while((n=stream.read(buf))!=-1){
        if(n>256-out.size())throw new IOException("P48_HOST_STREAM_LIMIT");
        out.write(buf,0,n);
      }
      sink.set(new String(out.toByteArray(),StandardCharsets.US_ASCII));
    }catch(Exception e){sink.set("P48_READER_ERROR");}
    finally{readers.countDown();}
  }
  private void verifyAsync(int exit){
    new Thread(()->{
      boolean done;
      try{done=readers.await(4,TimeUnit.SECONDS);}
      catch(InterruptedException e){Thread.currentThread().interrupt();done=false;}
      final boolean completeReaders=done;
      main.post(()->{
        if(failed||complete)return;
        if(!completeReaders || exit!=0 || proxy==null ||
           proxy.terminalReason()!=P37RemoteProcess.TerminalReason.REMOTE_EXIT||
           proxy.isAlive() || !stderr.get().isEmpty() ||
           !stdout.get().equals(exactOriginalArm64Node?
                "UID="+workerUid+"\nBOOT\nREADY\n":workerUid+"\n") ||
           !stderr.get().equals(exactOriginalArm64Node?"P50-STDERR\n":"")) {
          failClosed("P48_P37_STREAM_UID_OR_EOF_MISMATCH");return;
        }
        try {
          if(proxy.exitValue()!=0 || proxy.waitFor(0,TimeUnit.SECONDS)==false){
            failClosed("P48_PROCESS_WAIT_EXIT_MISMATCH");return;
          }
        }catch(InterruptedException e){
          Thread.currentThread().interrupt();
          failClosed("P48_PROCESS_WAIT_INTERRUPTED");return;
        }
        complete=true;
        if(exactOriginalArm64Node) {
          listener.report("P50_REAL_ORIGINAL_DSH_PACKAGE_EXACT_NODE_IN_ISOLATED_UID=PASS");
          listener.report("P50_PINNED_NODE_STREAM_STDERR_READY_EXIT=PASS");
          listener.report("P50_ORIGINAL_NODE_PRODUCTION_SCRIPTS=NOT_EXECUTED");
          listener.report("P50_REAL_DSH_ENGINEMANAGER_PROXY_HANDOFF=NO");
        }else {
          listener.report("P48_ORIGINAL_APK_ISOLATED_CHILD_UID_MATCHES_BINDER=PASS");
          listener.report("P48_P37_PROCESS_STDOUT_EOF_WAIT_EXIT=PASS");
          listener.report("P48_HOST_DID_NOT_EXECUTE_CHILD=PASS_SCOPE_LIMITED");
          listener.report("P48_REAL_PRODUCTION_DSH_NODE=NOT_STARTED");
        }
        listener.report("P48_FIXED_SIGNED_V139_APK=BLOCKED");
      });
    },"p48-host-process-verify").start();
  }
  private void failClosed(String code){
    if(failed||complete)return;
    failed=true;
    if(proxy!=null)proxy.onTransportLost();
    listener.fail(code);
  }
  public void close(){
    if(proxy!=null&&proxy.isAlive())proxy.destroyForcibly();
    if(!complete&&!failed)failClosed("P48_HOST_CLOSED");
  }
}
