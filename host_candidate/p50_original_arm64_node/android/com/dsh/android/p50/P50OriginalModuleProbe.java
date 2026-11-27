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
  private P50OriginalEngineConfig originalEngine;
  private final AtomicReference<String> sourceState=new AtomicReference<>("NOT_STARTED");
  private final long epoch=SystemClock.elapsedRealtimeNanos();
  private final android.os.IBinder.DeathRecipient workerDied=()->main.post(()->deny("BINDER_DEATH"));
  private boolean deathLinked;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(closed.get()||intake==null)return;
      try{
        P68AndroidBinderIntake.Result result=intake.accept(message);
        if(result==P68AndroidBinderIntake.Result.REJECTED){
          report("ORIGINAL_CONFIG_MODULE_SOURCE="+sourceState.get());
          deny("BINDER_PROTOCOL_REJECTED");return;
        }
        if(result==P68AndroidBinderIntake.Result.FAIL){
          // Only inspect this bounded diagnostic after UID/session/order have
          // authenticated FAIL. It never authorizes or resurrects a Process.
          report("ORIGINAL_CONFIG_SUPERVISOR_STAGE="+
              P50OriginalNodeFixedChild.failureStageName(message.arg1));
          if(message.arg1==6&&message.arg2>=0&&message.arg2<=255)
            report("ORIGINAL_CONFIG_SUPERVISOR_CHILD_EXIT="+message.arg2);
          report("ORIGINAL_CONFIG_MODULE_SOURCE="+sourceState.get());
          deny("SUPERVISOR_FAILURE");return;
        }
        if(result==P68AndroidBinderIntake.Result.CHILD_STARTED){
          if(handedOut){deny("DUPLICATE_CHILD");return;}
          handedOut=true;
          process=(P37RemoteProcess)intake.processAfterAuthenticatedChildStart();
          P184ChildStartReceipt receipt=intake.takeVerifiedChildStartReceipt();
          if(process==null||receipt==null){
            deny("START_RECEIPT");return;
          }
          runOriginal(process,receipt);
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
    Thread prepare=new Thread(()->{
      try{
        originalEngine=P50OriginalEngineConfig.prepare(host,session,epoch);
        main.post(()->{if(!closed.get())startTransport();else originalEngine.close();});
      }catch(Exception denied){main.post(()->deny("ORIGINAL_ENGINE_PREPARATION"));}
    },"dsh-original-config-prepare");
    prepare.setDaemon(true);prepare.start();
  }
  private void startTransport(){
    try{
      worker.getBinder().linkToDeath(workerDied,0);deathLinked=true;
      pipes=P68AndroidBinderIntake.HostPipes.create();
      intake=new P68AndroidBinderIntake(session,new P37RemoteProcess.RemoteControl(){
        public void requestGracefulStop(){control(P48FixedIsolatedChild.STOP);}
        public void requestForceStop(){control(P48FixedIsolatedChild.KILL);}
      },pipes,epoch);
      Message start=Message.obtain(null,P48FixedIsolatedChild.START);
      Bundle data=new Bundle();data.putString("session",session);
      data.putString("p50_mode","p50-original-fresh-config");
      data.putBundle("process_pipes",pipes.workerBundle());
      start.setData(data);start.replyTo=inbox;worker.send(start);
      main.postDelayed(()->{if(!closed.get())deny("DEADLINE");},100000);
      report("ORIGINAL_CONFIG_ENGINE_MANAGER_AND_HTTP_READY=NOT_WIRED");
    }catch(IOException|RemoteException|RuntimeException failure){deny("START_TRANSPORT");}
    finally{
      if(pipes!=null&&!pipes.closeWorkerCopies())deny("PIPE_OWNERSHIP_RELEASE");
    }
  }
  private void control(int kind){
    Message message=Message.obtain(null,kind);Bundle data=new Bundle();
    data.putString("session",session);message.setData(data);
    try{worker.send(message);}catch(RemoteException ignored){}
  }
  private void runOriginal(P37RemoteProcess child,P184ChildStartReceipt receipt){
    AtomicReference<String> failure=new AtomicReference<>();
    CountDownLatch inputDone=new CountDownLatch(1);
    Thread input=new Thread(()->{
      sourceState.set("STREAMING");
      try(InputStream original=host.getAssets().open("engine.bin");OutputStream stdin=child.getOutputStream()){
        P50ModuleStream.writeOriginal(original,stdin);sourceState.set("VERIFIED_COMPLETE");
      }catch(Exception denied){sourceState.set("FAILED");failure.compareAndSet(null,"MODULE_TRANSFER");}
      finally{inputDone.countDown();}
    },"dsh-original-module-stream");
    input.setDaemon(true);input.start();
    Thread invoke=new Thread(()->{
      try{
        // Original runDumpConfig creates its own two reader threads, performs
        // its own timed wait, and constructs its own original DumpResult.
        Object result=originalEngine.invoke(child,receipt);
        int exit=(Integer)P50OriginalEngineConfig.value(result,"getExitCode");
        byte[] output=((String)P50OriginalEngineConfig.value(result,"getStdout")).getBytes(StandardCharsets.UTF_8);
        String error=(String)P50OriginalEngineConfig.value(result,"getStderr");
        String sha=hash(output);
        boolean valid=inputDone.await(5,TimeUnit.SECONDS)&&failure.get()==null&&exit==0&&
            child.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT&&
            output.length==44560&&"87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5".equals(sha)&&
            error.equals("DSH_ORIGINAL_CONFIG_MODULES=69\n");
        main.post(()->{
          if(closed.get())return;
          report("ORIGINAL_ENGINE_RUN_DUMP_CONFIG=INVOKED");
          report("ORIGINAL_ENGINE_CONFIG_CHILD_EXIT="+exit);
          report("ORIGINAL_ENGINE_CONFIG_SHA256="+sha+" bytes="+output.length);
          if(valid){
            report("ORIGINAL_ENGINE_CONFIG_P47_AUTHENTICATED_P37_HANDOFF=PASS");
            report("ORIGINAL_ENGINE_CONFIG_ORIGINAL_READERS_WAIT_AND_RESULT=PASS");
            report("ORIGINAL_ENGINE_CONFIG_FRESH_PROFILE_ONLY=YES");
            report("ORIGINAL_ENGINE_CONFIG_SIDECAR_NOT_PRODUCTION=YES");
            report("ORIGINAL_CONFIG_ENGINE_MANAGER_AND_HTTP_READY=NOT_WIRED");close();
          }else{report("ORIGINAL_CONFIG_MODULE_SOURCE="+sourceState.get());deny("ORIGINAL_ENGINE_RESULT");}
        });
      }catch(Exception denied){main.post(()->deny("ORIGINAL_ENGINE_INVOCATION"));}
    },"dsh-original-engine-runDumpConfig");
    invoke.setDaemon(true);invoke.start();
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
    if(originalEngine!=null)originalEngine.close();
    if(intake!=null)intake.disconnected();
    if(process!=null&&process.isAlive())process.destroyForcibly();
    if(pipes!=null)pipes.close();
    if(deathLinked){worker.getBinder().unlinkToDeath(workerDied,0);deathLinked=false;}
  }
}
