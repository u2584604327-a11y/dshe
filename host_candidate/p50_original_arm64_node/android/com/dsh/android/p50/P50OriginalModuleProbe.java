package com.dsh.android.p50;

import android.app.Activity;
import android.os.*;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p68.P68AndroidBinderIntake;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Genuine original default-config only, permissionless P51 sidecar, not EngineManager READY. */
public final class P50OriginalModuleProbe implements AutoCloseable {
  public interface Reporter {void report(String fixedStatus);}
  private final Activity host;
  private final Messenger worker;
  private final String session;
  private final Reporter reporter;
  private final Handler main=new Handler(Looper.getMainLooper());
  private final AtomicBoolean closed=new AtomicBoolean();
  private P68AndroidBinderIntake.HostPipes pipes;
  private P68AndroidBinderIntake intake;
  private P37RemoteProcess process;
  private boolean started,handedOut;
  private final long epoch=SystemClock.elapsedRealtimeNanos();
  private final android.os.IBinder.DeathRecipient workerDied=()->main.post(()->deny("BINDER_DEATH"));
  private boolean deathLinked;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(closed.get()||intake==null)return;
      try{
        P68AndroidBinderIntake.Result result=intake.accept(message);
        if(result==P68AndroidBinderIntake.Result.REJECTED||result==P68AndroidBinderIntake.Result.FAIL){
          deny("AUTHENTICATED_CHILD_REJECTED");return;
        }
        if(result==P68AndroidBinderIntake.Result.CHILD_STARTED){
          if(handedOut){deny("DUPLICATE_CHILD");return;}
          handedOut=true;
          process=(P37RemoteProcess)intake.processAfterAuthenticatedChildStart();
          P184ChildStartReceipt receipt=intake.takeVerifiedChildStartReceipt();
          if(process==null||receipt==null||!receipt.consume(process,session,epoch)||
             receipt.consume(process,session,epoch)){
            deny("START_RECEIPT");return;
          }
          report("ORIGINAL_CONFIG_AUTHENTICATED_CHILD_AND_ONE_USE_RECEIPT=PASS");
          runOriginal(process);
        }
      }catch(RuntimeException invalid){deny("INVALID_BINDER_FRAME");}
    }
  });

  public P50OriginalModuleProbe(Activity host,Messenger authenticatedWorker,String session,Reporter reporter){
    if(host==null||authenticatedWorker==null||reporter==null||session==null||
       !session.matches("[0-9a-f]{64}")||
       !"com.dsh.p51.isolatedprobe".equals(host.getPackageName())||epoch<=0)
      throw new SecurityException("P50_PERMISSIONLESS_SIDECAR_ONLY");
    this.host=host;this.worker=authenticatedWorker;this.session=session;this.reporter=reporter;
  }
  public void start(){
    if(started||closed.get())throw new IllegalStateException("P50_ONE_USE_PROBE");
    started=true;
    try{
      worker.getBinder().linkToDeath(workerDied,0);deathLinked=true;
      pipes=P68AndroidBinderIntake.HostPipes.create();
      intake=new P68AndroidBinderIntake(session,new P37RemoteProcess.RemoteControl(){
        public void requestGracefulStop(){control(P48FixedIsolatedChild.STOP);}
        public void requestForceStop(){control(P48FixedIsolatedChild.KILL);}
      },pipes,epoch);
      Message start=Message.obtain(null,P48FixedIsolatedChild.START);
      Bundle data=new Bundle();data.putString("session",session);
      data.putString("p50_mode","p50-original-default-config");
      data.putBundle("process_pipes",pipes.workerBundle());
      start.setData(data);start.replyTo=inbox;worker.send(start);
      main.postDelayed(()->{if(!closed.get())deny("DEADLINE");},100000);
      report("ORIGINAL_CONFIG_ENGINE_MANAGER_AND_HTTP_READY=NOT_WIRED");
    }catch(IOException|RemoteException|RuntimeException failure){deny("START_TRANSPORT");}
    finally{if(pipes!=null)pipes.closeWorkerCopies();}
  }
  private void control(int kind){
    Message message=Message.obtain(null,kind);Bundle data=new Bundle();
    data.putString("session",session);message.setData(data);
    try{worker.send(message);}catch(RemoteException ignored){}
  }
  private void runOriginal(P37RemoteProcess child){
    CountDownLatch finished=new CountDownLatch(3);
    AtomicReference<String> failure=new AtomicReference<>();
    ByteArrayOutputStream output=new ByteArrayOutputStream(),error=new ByteArrayOutputStream();
    Thread input=new Thread(()->{
      try(InputStream original=host.getAssets().open("engine.bin");OutputStream stdin=child.getOutputStream()){
        P50ModuleStream.writeOriginal(original,stdin);
      }catch(Exception denied){failure.compareAndSet(null,"MODULE_TRANSFER");child.destroyForcibly();}
      finally{finished.countDown();}
    },"dsh-original-module-stream");
    Thread stdout=reader(child.getInputStream(),output,1024*1024,finished,failure,child);
    Thread stderr=reader(child.getErrorStream(),error,8192,finished,failure,child);
    input.setDaemon(true);input.start();stdout.start();stderr.start();
    Thread verify=new Thread(()->{
      try{
        if(!child.waitFor(95,TimeUnit.SECONDS)||!finished.await(5,TimeUnit.SECONDS)){
          main.post(()->deny("CHILD_OR_STREAM_TIMEOUT"));return;
        }
        String sha=hash(output.toByteArray());
        String diagnostics=new String(error.toByteArray(),StandardCharsets.UTF_8);
        boolean valid=failure.get()==null&&child.exitValue()==0&&
            child.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT&&
            output.size()==44560&&
            "87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5".equals(sha)&&
            diagnostics.equals("DSH_ORIGINAL_CONFIG_MODULES=69\n");
        main.post(()->{
          if(closed.get())return;
          if(valid){
            report("ORIGINAL_CONFIG_ARM64_NODE_PRODUCTION_MODULES=PASS modules=69 bytes=44560");
            report("ORIGINAL_CONFIG_SHA256="+sha);
            report("ORIGINAL_CONFIG_ENGINE_MANAGER_AND_HTTP_READY=NOT_WIRED");
            close();
          }else{
            report("ORIGINAL_CONFIG_OBSERVED_SHA256="+sha+" bytes="+output.size());
            String prefix="DSH_ORIGINAL_CONFIG_ERROR=";
            for(String line:diagnostics.split("\n"))if(line.startsWith(prefix)&&
                line.substring(prefix.length()).matches("[A-Z0-9_]{1,100}"))report(line);
            deny("ORIGINAL_CONFIG_NOT_VERIFIED");
          }
        });
      }catch(Exception denied){main.post(()->deny("PROCESS_LIFECYCLE"));}
    },"dsh-original-module-verify");
    verify.setDaemon(true);verify.start();
  }
  private static Thread reader(InputStream input,ByteArrayOutputStream sink,int limit,
      CountDownLatch finished,AtomicReference<String> failure,P37RemoteProcess child){
    Thread thread=new Thread(()->{
      try(InputStream stream=input){
        byte[] bytes=new byte[8192];int n;
        while((n=stream.read(bytes))!=-1){
          if(n>limit-sink.size())throw new IOException("OUTPUT_BOUND");
          sink.write(bytes,0,n);
        }
      }catch(Exception denied){failure.compareAndSet(null,"STREAM_READ");child.destroyForcibly();}
      finally{finished.countDown();}
    },"dsh-original-config-reader");
    thread.setDaemon(true);return thread;
  }
  private static String hash(byte[] value)throws Exception{
    StringBuilder out=new StringBuilder(64);
    for(byte b:MessageDigest.getInstance("SHA-256").digest(value))
      out.append(String.format(Locale.ROOT,"%02x",b&255));
    return out.toString();
  }
  private void report(String status){if(!closed.get())reporter.report(status);}
  private void deny(String code){
    if(closed.get())return;
    report("ORIGINAL_CONFIG_ARM64_EXECUTION=DENY_"+code);close();
  }
  @Override public void close(){
    if(!closed.compareAndSet(false,true))return;
    if(intake!=null)intake.disconnected();
    if(process!=null&&process.isAlive())process.destroyForcibly();
    if(pipes!=null)pipes.close();
    if(deathLinked){worker.getBinder().unlinkToDeath(workerDied,0);deathLinked=false;}
  }
}
