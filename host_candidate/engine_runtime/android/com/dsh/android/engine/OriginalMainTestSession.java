package com.dsh.android.engine;
import android.content.*;import android.os.*;
import android.system.ErrnoException;
import android.system.OsConstants;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p50.P50ModuleStream;
import com.dsh.android.p68.P68AndroidBinderIntake;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;import java.security.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import java.util.function.LongConsumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** One authenticated, separately named Android isolated instance, TEST ONLY.
 * No argv/path/owner supplied by an Intent or Binder payload; no production
 * P47 registration. The physical main test can reuse the exact runtime wire.
 */
final class OriginalMainTestSession implements AutoCloseable {
  private static final String MODULE_RESOURCE="assets/engine.bin";
  private static final long MODULE_RESOURCE_BYTES=57_724_933L;
  enum LaunchPhase { RESERVATION, RESOURCE_TRANSFER, LOOPBACK_TRANSPORT }
  static final class ResourceFailure extends IOException {
    private ResourceFailure(String code){super(code);}
  }
  private final Context context;private final LongConsumer progress;private final Handler main=new Handler(Looper.getMainLooper());
  private final AtomicBoolean closed=new AtomicBoolean();
  private final AtomicBoolean bindRequested=new AtomicBoolean(),childClaimed=new AtomicBoolean();
  private final CompletableFuture<P37RemoteProcess> started=new CompletableFuture<>();
  private final CountDownLatch terminalObserved=new CountDownLatch(1);
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
  private volatile long resourceWireBytes;
  private volatile String earlyChildFailure="NONE";
  private volatile String workerStdinTermination="UNREPORTED";
  private volatile String observedChildExit="UNREPORTED";
  private volatile LaunchPhase launchPhase=LaunchPhase.RESERVATION;
  private final IBinder.DeathRecipient died=()->main.post(()->reject("BINDER_DEATH"));
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(closed.get()||intake==null)return;
      try{
        P68AndroidBinderIntake.Result result=intake.accept(message);
        if(result==P68AndroidBinderIntake.Result.REJECTED){reject("WORKER_PROTOCOL");return;}
        if(result==P68AndroidBinderIntake.Result.FAIL){
          if(message.arg1==6&&message.arg2>=0&&message.arg2<=255)
            observedChildExit=Integer.toString(message.arg2);
          reject("SUPERVISOR_"+com.dsh.android.p50.P50OriginalNodeFixedChild.failureStageName(message.arg1));
          return;
        }
        if(result==P68AndroidBinderIntake.Result.EXIT){
          P37RemoteProcess exact=process;
          if(exact!=null&&exact.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT){
            observedChildExit=Integer.toString(exact.exitValue());
            workerStdinTermination=P68AndroidBinderIntake.WorkerPipes.stdinTerminationName(message.arg1);
          }
          terminalObserved.countDown();
          return;
        }
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
  long resourceWireBytes(){return resourceWireBytes;}
  String earlyChildFailure(){return earlyChildFailure;}
  String observedChildExit(){return observedChildExit;}
  String workerStdinTermination(){return workerStdinTermination;}
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
    try{transferResources(exact);}
    catch(ResourceFailure denied){
      if("MAIN_OWNER_RESOURCE_PIPE_CLOSED".equals(denied.getMessage()))observeEarlyChildFailure(exact);
      throw denied;
    }
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
  private void observeEarlyChildFailure(P37RemoteProcess exact){
    if(closed.get())return;
    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2);
    // The transport was never admitted. Releasing stdout allows the worker to
    // drain it, and the reader below consumes only bounded diagnostic stderr.
    try{exact.getInputStream().close();}catch(IOException ignored){}
    Thread reader=new Thread(()->earlyChildFailure=OriginalMainStartup.earlyChildFailure(exact.getErrorStream()),
        "dsh-main-rejected-stderr");
    reader.setDaemon(true);
    reader.start();
    try{
      terminalObserved.await(Math.max(0,deadline-System.nanoTime()),TimeUnit.NANOSECONDS);
      long remaining=deadline-System.nanoTime();
      if(remaining>0)reader.join(Math.max(1,TimeUnit.NANOSECONDS.toMillis(remaining)));
    }catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
  }
  private void transferResources(P37RemoteProcess exact)throws IOException{
    OutputStream pipe=new FilterOutputStream(exact.getOutputStream()){
      private long next=32L*1024*1024;
      @Override public void write(int value)throws IOException{
        try{out.write(value);}catch(IOException failure){throw pipeFailure(failure);}
        advanced(1);
      }
      @Override public void write(byte[] bytes,int offset,int length)throws IOException{
        try{out.write(bytes,offset,length);}catch(IOException failure){throw pipeFailure(failure);}
        advanced(length);
      }
      @Override public void flush()throws IOException{
        try{out.flush();}catch(IOException failure){throw pipeFailure(failure);}
      }
      private void advanced(int count){
        resourceWireBytes+=count;
        if(progress!=null&&resourceWireBytes>=next){
          next=resourceWireBytes+32L*1024*1024;
          progress.accept(resourceWireBytes);
        }
      }
    };
    // Use the fixed base-APK member from the authenticated TEST host package.
    // P50/P77 still check the complete original tree before flushing its seal.
    try(ZipFile apk=openResourceApk()){
      ZipEntry entry=apk.getEntry(MODULE_RESOURCE);
      if(entry==null||entry.isDirectory()||entry.getSize()!=MODULE_RESOURCE_BYTES)
        throw new ResourceFailure("MAIN_OWNER_RESOURCE_ENTRY");
      try(InputStream original=apk.getInputStream(entry)){
        // P50 flushes the final frame after checking the seal. Leave the pipe
        // open for the HTTP preface.
        P50ModuleStream.writeOriginalForService(original,new BufferedOutputStream(pipe,65536));
      }
    }catch(ResourceFailure fixed){throw fixed;}
    catch(IOException failure){throw new ResourceFailure("MAIN_OWNER_RESOURCE_READ_OR_SEAL");}
  }
  private ZipFile openResourceApk()throws ResourceFailure{
    try{return new ZipFile(context.getApplicationInfo().sourceDir);}
    catch(IOException failure){throw new ResourceFailure("MAIN_OWNER_RESOURCE_APK_OPEN");}
  }
  private static ResourceFailure pipeFailure(IOException failure){
    Throwable cause=failure;
    for(int depth=0;cause!=null&&depth<8;depth++,cause=cause.getCause()){
      if(cause instanceof ErrnoException){
        int errno=((ErrnoException)cause).errno;
        if(errno==OsConstants.EPIPE)return new ResourceFailure("MAIN_OWNER_RESOURCE_PIPE_CLOSED");
        if(errno==OsConstants.EBADF)return new ResourceFailure("MAIN_OWNER_RESOURCE_PIPE_FD");
      }
    }
    return new ResourceFailure("MAIN_OWNER_RESOURCE_PIPE_IO");
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
    terminalObserved.countDown();
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
