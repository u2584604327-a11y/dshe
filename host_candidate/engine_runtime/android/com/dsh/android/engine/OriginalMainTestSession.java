package com.dsh.android.engine;
import android.content.*;import android.os.*;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p50.P50ModuleStream;
import com.dsh.android.p68.P68AndroidBinderIntake;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;import java.security.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.util.function.LongConsumer;

/** One authenticated, separately named Android isolated instance, TEST ONLY.
 * No argv/path/owner supplied by an Intent or Binder payload; no production
 * P47 registration. The physical main test can reuse the exact runtime wire.
 */
final class OriginalMainTestSession implements AutoCloseable {
  enum LaunchPhase { RESERVATION, RESOURCE_TRANSFER, LOOPBACK_TRANSPORT }
  private final Context context;private final LongConsumer progress;private final Handler main=new Handler(Looper.getMainLooper());
  private final AtomicBoolean closed=new AtomicBoolean();
  private final AtomicBoolean bindRequested=new AtomicBoolean(),childClaimed=new AtomicBoolean();
  private final CompletableFuture<P37RemoteProcess> started=new CompletableFuture<>();
  final String session;final long epoch=SystemClock.elapsedRealtimeNanos();
  private long requestSequence=1;private boolean bound,linked,handedOut;
  private volatile Messenger worker;
  private volatile P68AndroidBinderIntake.HostPipes pipes;
  private P68AndroidBinderIntake intake;
  private volatile P37RemoteProcess process;
  private HttpProcessTransport launchTransport;
  private OriginalAndroidWebLaunch launchOwner;
  private boolean transportOpened,handoffOffered;
  private volatile String failure="NONE";
  private volatile LaunchPhase launchPhase=LaunchPhase.RESERVATION;
  private final IBinder.DeathRecipient died=()->main.post(()->reject("BINDER_DEATH"));
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(closed.get()||intake==null)return;
      try{
        P68AndroidBinderIntake.Result result=intake.accept(message);
        if(result==P68AndroidBinderIntake.Result.REJECTED){reject("WORKER_PROTOCOL");return;}
        if(result==P68AndroidBinderIntake.Result.FAIL){reject("SUPERVISOR_"+com.dsh.android.p50.P50OriginalNodeFixedChild.failureStageName(message.arg1));return;}
        if(result!=P68AndroidBinderIntake.Result.CHILD_STARTED)return;
        if(handedOut){reject("CHILD_REPLAY");return;}handedOut=true;
        P37RemoteProcess received=(P37RemoteProcess)intake.processAfterAuthenticatedChildStart();
        P184ChildStartReceipt receipt=intake.takeVerifiedChildStartReceipt();
        if(received==null||receipt==null||!receipt.consume(received,session,epoch)){reject("CHILD_RECEIPT");return;}
        process=received;if(closed.get()||!started.complete(received))received.destroyForcibly();
      }catch(RuntimeException bad){reject("BINDER_FRAME");}
    }
  });
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      if(closed.get())return;
      if(!context.getPackageName().equals(name.getPackageName())||!OriginalMainIsolatedService.class.getName().equals(name.getClassName())){reject("SERVICE_COMPONENT");return;}
      worker=new Messenger(binder);
      try{
        binder.linkToDeath(died,0);linked=true;pipes=P68AndroidBinderIntake.HostPipes.create();
        intake=new P68AndroidBinderIntake(session,new P37RemoteProcess.RemoteControl(){
          public void requestGracefulStop(){control(P48FixedIsolatedChild.STOP);}
          public void requestForceStop(){control(P48FixedIsolatedChild.KILL);}
        },pipes,epoch);
        Bundle data=new Bundle();data.putString("session",session);data.putLong("epoch",epoch);data.putLong("request_seq",1);
        data.putLong("issued_ms",SystemClock.elapsedRealtime());data.putBundle("process_pipes",pipes.workerBundle());
        Message request=Message.obtain(null,P48FixedIsolatedChild.START);request.setData(data);request.replyTo=inbox;
        synchronized(OriginalMainTestSession.this){
          if(!closed.get())worker.send(request);
        }
      }catch(IOException|RemoteException|RuntimeException bad){reject("START_TRANSFER");}
      finally{if(pipes!=null){if(!pipes.closeWorkerCopies())reject("PIPE_OWNERSHIP");if(closed.get())pipes.close();}}
    }
    @Override public void onServiceDisconnected(ComponentName name){reject("SERVICE_DISCONNECTED");}
    @Override public void onBindingDied(ComponentName name){reject("BINDING_DIED");}
    @Override public void onNullBinding(ComponentName name){reject("NULL_BINDING");}
  };
  OriginalMainTestSession(Context host,LongConsumer progress){
    if(host==null||Build.VERSION.SDK_INT<35||android.os.Process.isIsolated()||
       !"com.dsh.p51.networkprobe".equals(host.getPackageName())||
       host.checkSelfPermission("android.permission.INTERNET")!=android.content.pm.PackageManager.PERMISSION_GRANTED)
      throw new SecurityException("MAIN_TEST_CONTEXT_REQUIRED");
    context=host.getApplicationContext();this.progress=progress;byte[] random=new byte[32];new SecureRandom().nextBytes(random);
    StringBuilder id=new StringBuilder();for(byte b:random)id.append(String.format(Locale.ROOT,"%02x",b&255));session=id.toString();Arrays.fill(random,(byte)0);
  }
  void bind(){
    if(!bindRequested.compareAndSet(false,true))throw new IllegalStateException("MAIN_BIND_ALREADY_REQUESTED");
    main.post(()->{
      if(closed.get())return;
      try{
        // A new instance name forces a distinct lease/isolated process for each
        // generation; old Binder callbacks remain bound to this exact object.
        bound=context.bindIsolatedService(new Intent(context,OriginalMainIsolatedService.class),Context.BIND_AUTO_CREATE,
            "main_"+session,task->main.post(task),connection);
        if(!bound)reject("BIND_REJECTED");
      }catch(RuntimeException denied){reject("BIND_EXCEPTION");}
    });
  }
  P37RemoteProcess awaitChild()throws Exception{
    if(Looper.myLooper()==Looper.getMainLooper())throw new IllegalStateException("MAIN_TEST_BACKGROUND_REQUIRED");
    if(!bindRequested.get()||!childClaimed.compareAndSet(false,true))throw new IOException("MAIN_CHILD_CLAIM_DENIED");
    try{
      P37RemoteProcess child=started.get(15,TimeUnit.SECONDS);
      if(closed.get())throw new IOException("MAIN_TEST_SESSION_CLOSED");
      return child;
    }catch(InterruptedException interrupted){Thread.currentThread().interrupt();close();throw new InterruptedIOException("MAIN_TEST_CHILD_INTERRUPTED");}
    catch(ExecutionException|TimeoutException bad){close();throw new IOException("MAIN_TEST_CHILD_"+failure);}
  }
  String failure(){return failure;}
  LaunchPhase launchPhase(){return launchPhase;}
  String childState(){P37RemoteProcess child=process;return child==null?"NONE":child.terminalReason().name();}
  synchronized String transportFailure(){return launchTransport==null?"NONE/NONE":launchTransport.failure();}
  HttpProcessTransport openLaunchTransport(P37RemoteProcess exact,OriginalAndroidWebLaunch launch,
      DurableSessionSnapshot store)throws IOException{
    synchronized(this){
      if(!ownsReservation(launch,exact))
        throw new IOException("MAIN_LAUNCH_AUTHENTICATED_CHILD_REQUIRED");
      transportOpened=true;
    }
    launchPhase=LaunchPhase.RESOURCE_TRANSFER;
    transferResources(exact);
    if(closed.get()||!ownsChild(exact))throw new IOException("MAIN_TEST_SESSION_CLOSED");
    launchPhase=LaunchPhase.LOOPBACK_TRANSPORT;
    HttpProcessTransport transport=HttpProcessTransport.forOriginalWebLaunch(exact,session,epoch,launch.plan,store);
    synchronized(this){
      if(!closed.get()){
        launchTransport=transport;
        return transport;
      }
    }
    transport.close();
    throw new IOException("MAIN_TEST_SESSION_CLOSED");
  }
  private void transferResources(P37RemoteProcess exact)throws IOException{
    OutputStream output=new FilterOutputStream(exact.getOutputStream()){
      private long sent,next=32L*1024*1024;
      @Override public void write(int value)throws IOException{out.write(value);advanced(1);}
      @Override public void write(byte[] bytes,int offset,int length)throws IOException{out.write(bytes,offset,length);advanced(length);}
      private void advanced(int count){
        sent+=count;
        if(progress!=null&&sent>=next){next=sent+32L*1024*1024;progress.accept(sent);}
      }
    };
    try(InputStream original=context.getAssets().open("engine.bin")){
      P50ModuleStream.writeOriginalForService(original,output);
    }
  }
  private boolean ownsChild(P37RemoteProcess exact){
    return childClaimed.get()&&exact!=null&&process==exact&&exact.isAlive();
  }
  synchronized boolean ownsReservation(OriginalAndroidWebLaunch owner,P37RemoteProcess exact){
    return !closed.get()&&handoffOffered&&launchOwner==owner&&!transportOpened&&ownsChild(exact);
  }
  synchronized boolean ownsLaunch(OriginalAndroidWebLaunch owner,HttpProcessTransport transport){
    return !closed.get()&&launchOwner==owner&&launchTransport==transport&&ownsChild(process);
  }
  synchronized boolean reserveHandoff(OriginalAndroidWebLaunch owner,P37RemoteProcess exact){
    if(closed.get()||handoffOffered||!ownsChild(exact))return false;
    launchOwner=owner;
    handoffOffered=true;
    return true;
  }
  private synchronized void control(int kind){
    if(worker==null)return;Bundle data=new Bundle();data.putString("session",session);data.putLong("epoch",epoch);data.putLong("request_seq",++requestSequence);
    Message request=Message.obtain(null,kind);request.setData(data);try{worker.send(request);}catch(RemoteException ignored){}
  }
  private void reject(String fixed){if(!closed.get())failure=fixed;started.completeExceptionally(new IOException("MAIN_TEST_SESSION_DENIED"));close();}
  @Override public void close(){
    HttpProcessTransport active;
    synchronized(this){
      if(!closed.compareAndSet(false,true))return;
      active=launchTransport;
    }
    if(active!=null)active.revokeReady();
    started.completeExceptionally(new IOException("MAIN_TEST_SESSION_CLOSED"));
    if(process!=null&&process.isAlive())process.destroyForcibly();
    if(pipes!=null)pipes.close();
    if(active!=null){
      if(Looper.myLooper()==Looper.getMainLooper()){
        Thread release=new Thread(active::close,"dsh-owned-launch-revoke");
        release.setDaemon(true);release.start();
      }else active.close();
    }
    main.post(()->{
      if(intake!=null)intake.disconnected();
      if(linked&&worker!=null){worker.getBinder().unlinkToDeath(died,0);linked=false;}
      if(bound){try{context.unbindService(connection);}catch(IllegalArgumentException ignored){}bound=false;}
    });
  }
}
