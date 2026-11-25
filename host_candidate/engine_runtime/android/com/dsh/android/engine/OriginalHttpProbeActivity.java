package com.dsh.android.engine;
import android.app.Activity;import android.content.*;import android.os.*;import android.widget.*;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p50.P50ModuleStream;
import com.dsh.android.p68.P68AndroidBinderIntake;
import com.dsh.android.p68.P184ChildStartReceipt;
import com.dsh.p37.P37RemoteProcess;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.security.*;import java.util.*;
import java.util.concurrent.*;import java.util.concurrent.atomic.*;

/** Separate, fixed HTTP component acceptance only. No original DSH owner,
 * storage, intent-supplied arguments, frontend token display or READY claim. */
public final class OriginalHttpProbeActivity extends Activity {
  private final Handler main=new Handler(Looper.getMainLooper());
  private final AtomicBoolean closed=new AtomicBoolean();
  private final StringBuilder status=new StringBuilder();private TextView text;
  private String session;private final long epoch=SystemClock.elapsedRealtimeNanos();
  private long requestSeq=1;private boolean bound,deathLinked,handedOut;
  private Messenger worker;private P68AndroidBinderIntake intake;
  private P68AndroidBinderIntake.HostPipes pipes;private P37RemoteProcess raw;
  private HttpProcessTransport transport;
  private final AtomicReference<String> startupStage=new AtomicReference<>("BIND");
  private final AtomicReference<String> childError=new AtomicReference<>("NONE");
  private final IBinder.DeathRecipient workerDied=()->main.post(()->deny("BINDER_DEATH"));
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(closed.get()||intake==null)return;
      try{
        P68AndroidBinderIntake.Result result=intake.accept(message);
        if(result==P68AndroidBinderIntake.Result.REJECTED){deny("WORKER_PROTOCOL");return;}
        if(result==P68AndroidBinderIntake.Result.FAIL){
          report("ORIGINAL_HTTP_WORKER_FAILURE_STAGE="+com.dsh.android.p50.P50OriginalNodeFixedChild.failureStageName(message.arg1));
          if(message.arg1==6&&message.arg2!=Integer.MIN_VALUE)report("ORIGINAL_HTTP_SUPERVISOR_CHILD_EXIT="+message.arg2);
          reportRuntimeState();
          deny("AUTHENTICATED_WORKER_FAILURE");return;
        }
        if(result==P68AndroidBinderIntake.Result.CHILD_STARTED){
          if(handedOut){deny("CHILD_REPLAY");return;}handedOut=true;
          raw=(P37RemoteProcess)intake.processAfterAuthenticatedChildStart();
          P184ChildStartReceipt receipt=intake.takeVerifiedChildStartReceipt();
          if(raw==null||receipt==null||!receipt.consume(raw,session,epoch)){deny("CHILD_RECEIPT");return;}
          report("ORIGINAL_HTTP_AUTHENTICATED_ISOLATED_CHILD=PASS");
          Thread task=new Thread(OriginalHttpProbeActivity.this::verify,"original-http-component-acceptance");task.setDaemon(true);task.start();
        }
      }catch(RuntimeException bad){deny("BINDER_FRAME");}
    }
  });
  private final ServiceConnection connection=new ServiceConnection(){
    public void onServiceConnected(ComponentName name,IBinder binder){
      if(closed.get())return;worker=new Messenger(binder);
      try{
        binder.linkToDeath(workerDied,0);deathLinked=true;
        pipes=P68AndroidBinderIntake.HostPipes.create();
        intake=new P68AndroidBinderIntake(session,new P37RemoteProcess.RemoteControl(){
          public void requestGracefulStop(){control(P48FixedIsolatedChild.STOP);}
          public void requestForceStop(){control(P48FixedIsolatedChild.KILL);}
        },pipes,epoch);
        Bundle data=new Bundle();data.putString("session",session);data.putLong("epoch",epoch);data.putLong("request_seq",1);
        data.putLong("issued_ms",SystemClock.elapsedRealtime());data.putBundle("process_pipes",pipes.workerBundle());
        Message message=Message.obtain(null,P48FixedIsolatedChild.START);message.setData(data);message.replyTo=inbox;worker.send(message);
      }catch(IOException|RemoteException|RuntimeException bad){deny("START_TRANSFER");}
      finally{if(pipes!=null&&!pipes.closeWorkerCopies())deny("PIPE_OWNERSHIP");}
    }
    public void onServiceDisconnected(ComponentName name){deny("SERVICE_DISCONNECTED");}
    public void onBindingDied(ComponentName name){deny("BINDING_DIED");}
    public void onNullBinding(ComponentName name){deny("NULL_BINDING");}
  };
  @Override public void onCreate(Bundle saved){
    super.onCreate(saved);
    text=new TextView(this);text.setTextSize(13);text.setPadding(16,16,16,16);
    text.setOnLongClickListener(view->{android.content.ClipboardManager clipboard=(android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
      clipboard.setPrimaryClip(ClipData.newPlainText("HTTP component test status",status.toString()));return true;});
    ScrollView scroll=new ScrollView(this);scroll.addView(text);setContentView(scroll);
    if(Build.VERSION.SDK_INT<35||!"com.dsh.p51.networkprobe".equals(getPackageName())||android.os.Process.isIsolated()||
        checkSelfPermission("android.permission.INTERNET")!=android.content.pm.PackageManager.PERMISSION_GRANTED){deny("TEST_PACKAGE_OR_PERMISSION");return;}
    byte[] random=new byte[32];new SecureRandom().nextBytes(random);session=hex(random);
    report("HTTP_TEST_SEPARATE_PACKAGE_NOT_ORIGINAL_DSH=YES");report("HTTP_TEST_ORIGINAL_DSH_DATA=UNTOUCHED");
    report("HTTP_TEST_HOST_INTERNET_ONLY=YES");report("HTTP_TEST_LONG_PRESS_COPY=YES");
    report("HTTP_TEST_DEVICE_PAGE_SIZE="+android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE));
    report("ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED");report("ORIGINAL_DSH_HTTP_READY=NOT_WIRED");
    try{bound=bindService(new Intent(this,OriginalHttpIsolatedService.class),connection,BIND_AUTO_CREATE);if(!bound)deny("BIND_REJECTED");}
    catch(RuntimeException bad){deny("BIND_EXCEPTION");}
    main.postDelayed(()->{if(!closed.get()){reportRuntimeState();deny("DEADLINE_"+startupStage.get());}},110000);
  }
  private synchronized void control(int kind){
    if(worker==null)return;Bundle data=new Bundle();data.putString("session",session);data.putLong("epoch",epoch);data.putLong("request_seq",++requestSeq);
    Message message=Message.obtain(null,kind);message.setData(data);try{worker.send(message);}catch(RemoteException ignored){}
  }
  private void verify(){
    AtomicReference<String> stage=startupStage;
    Thread errors=null;
    try{
      stage(stage,"RESOURCE_TRANSFER");
      OutputStream resource=new FilterOutputStream(raw.getOutputStream()){
        long sent,next=16L*1024*1024;
        private void advanced(int bytes){
          sent+=bytes;if(sent<next)return;next=sent+16L*1024*1024;
          final long count=sent;main.post(()->report("ORIGINAL_HTTP_RESOURCE_WIRE_BYTES_SENT="+count));
        }
        @Override public void write(int value)throws IOException{out.write(value);advanced(1);}
        @Override public void write(byte[] bytes,int offset,int length)throws IOException{out.write(bytes,offset,length);advanced(length);}
      };
      try(InputStream original=getAssets().open("engine.bin")){P50ModuleStream.writeOriginalForService(original,resource);}
      if(closed.get())return;
      main.post(()->report("ORIGINAL_HTTP_RESOURCE_SOURCE=VERIFIED_COMPLETE"));
      stage(stage,"HTTP_TRANSPORT");transport=new HttpProcessTransport(raw,session,epoch,0);
      if(closed.get()){transport.close();return;}
      // Start consuming fixed diagnostics before awaiting LISTEN. A failure in
      // module initialization must not lose its error behind the listen guard.
      errors=new Thread(()->{try{
        InputStream err=transport.getErrorStream();String line;int total=0;
        while((line=boundedLine(err,256))!=null){if((total+=line.length())>8192)break;
          if(line.matches("DSH_ORIGINAL_HTTP_ERROR=[A-Z0-9_]{1,64}"))childError.set(line.substring(line.indexOf('=')+1));}
      }catch(IOException ignored){}},"original-http-fixed-diagnostics");errors.setDaemon(true);errors.start();
      if(!transport.awaitListening(15,TimeUnit.SECONDS))throw new IOException("LISTEN");
      stage(stage,"ORIGINAL_SERVICE_OUTPUT");
      InputStream out=transport.getInputStream();
      String urlLine=boundedLine(out,512),modulesLine=boundedLine(out,128),nativeLine=boundedLine(out,128);
      String prefix="DSH_ORIGINAL_HTTP_URL=";
      if(urlLine==null||!urlLine.startsWith(prefix)||modulesLine==null||!modulesLine.matches("DSH_ORIGINAL_HTTP_RESOURCE_MODULES=[0-9]+"))throw new IOException("SERVICE_OUTPUT");
      if(!"DSH_ORIGINAL_ANDROID_NATIVE_BINDING=PASS".equals(nativeLine))throw new IOException("ORIGINAL_NATIVE_BINDING");
      main.post(()->report("ORIGINAL_ANDROID_NATIVE_BINDING_AND_FIVE_INTERNAL_APIS=PASS"));
      URL login=new URL(urlLine.substring(prefix.length()));
      if(!"http".equals(login.getProtocol())||!"127.0.0.1".equals(login.getHost())||login.getPort()!=transport.port()||
          !"/".equals(login.getPath())||login.getUserInfo()!=null||login.getRef()!=null||login.getQuery()==null||!login.getQuery().matches("token=[A-Za-z0-9_-]{43}"))throw new IOException("PRIVATE_AUTH_URL");
      // URL, process token and cookie remain private. Never report these values.
      stage(stage,"AUTHENTICATION");
      HttpURLConnection unauth=(HttpURLConnection)new URL("http://127.0.0.1:"+transport.port()+"/").openConnection(java.net.Proxy.NO_PROXY);
      unauth.setReadTimeout(5000);if(unauth.getResponseCode()!=401)throw new IOException("NO_AUTH");unauth.disconnect();
      HttpURLConnection exchange=(HttpURLConnection)login.openConnection(java.net.Proxy.NO_PROXY);exchange.setInstanceFollowRedirects(false);exchange.setReadTimeout(5000);
      if(exchange.getResponseCode()!=303)throw new IOException("TOKEN_EXCHANGE");
      String cookie=exchange.getHeaderField("Set-Cookie");if(cookie==null||!cookie.contains("HttpOnly")||!cookie.contains("SameSite=Strict"))throw new IOException("COOKIE");
      cookie=cookie.split(";")[0];exchange.disconnect();
      stage(stage,"FRONTEND");HttpURLConnection page=(HttpURLConnection)new URL("http://127.0.0.1:"+transport.port()+"/").openConnection(java.net.Proxy.NO_PROXY);
      page.setRequestProperty("Cookie",cookie);page.setReadTimeout(5000);
      if(page.getResponseCode()!=200||!"1ad6f6c840655f6fc4551aaa48559c0e1cc5749547ac679b08a9ce369678c6c4".equals(hash(page.getInputStream(),2*1024*1024)))throw new IOException("FRONTEND_BYTES");page.disconnect();
      stage(stage,"FRONTEND_JS");HttpURLConnection javascript=(HttpURLConnection)new URL("http://127.0.0.1:"+transport.port()+"/assets/index-CN7NIWNw.js").openConnection(java.net.Proxy.NO_PROXY);
      javascript.setReadTimeout(5000);
      if(javascript.getResponseCode()!=200||!"4bc914bfbb6adbdd63953a29f63835eb7127defd2a973149d64cdab489f1a9a5".equals(hash(javascript.getInputStream(),2*1024*1024)))throw new IOException("JS_BYTES");javascript.disconnect();
      stage(stage,"HOST_FENCE");
      try(Socket socket=new Socket("127.0.0.1",transport.port())){
        socket.setSoTimeout(5000);socket.getOutputStream().write("GET /api HTTP/1.1\r\nHost: evil.invalid\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        String response=boundedLine(socket.getInputStream(),512);if(response==null||!response.startsWith("HTTP/1.1 403 "))throw new IOException("HOST_FENCE");
      }
      stage(stage,"NODE_EXIT");transport.destroy();
      if(!transport.waitFor(8,TimeUnit.SECONDS)||transport.exitValue()!=0||raw.terminalReason()!=P37RemoteProcess.TerminalReason.REMOTE_EXIT||!transport.failure().equals("NONE/NONE"))throw new IOException("CHILD_EXIT");
      int loaded=Integer.parseInt(modulesLine.substring(modulesLine.indexOf('=')+1));
      if(loaded<=69||loaded>30411)throw new IOException("MODULE_COUNT");
      final String modules=Integer.toString(loaded);
      main.post(()->{if(closed.get())return;
        report("ORIGINAL_HTTP_SEALED_RESOURCE_MODULES="+modules);
        report("ORIGINAL_HTTP_AUTH_FRONTEND_AND_JS_BYTES=PASS");report("ORIGINAL_HTTP_HOST_FENCE=PASS");report("ORIGINAL_HTTP_MODULE_TREE=VERIFIED_COMPLETE");report("ORIGINAL_HTTP_COMPONENT_CHILD_EXIT=0");
        report("ORIGINAL_HTTP_ANDROID_SSE_AND_RESTART=NOT_TESTED");report("ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED");
        report("ORIGINAL_DSH_HTTP_READY=NOT_WIRED");report("FORMAL_V139=BLOCKED");close();});
    }catch(Exception|LinkageError bad){
      if(errors!=null)try{errors.join(250);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();}
      main.post(()->{reportRuntimeState();report("ORIGINAL_HTTP_FIXED_CHILD_ERROR="+childError.get());deny(stage.get());});
    }
  }
  private void stage(AtomicReference<String> current,String value){current.set(value);main.post(()->report("ORIGINAL_HTTP_STAGE="+value));}
  private void reportRuntimeState(){
    if(raw!=null){report("ORIGINAL_HTTP_PROCESS_STATE="+raw.terminalReason().name());
      if(!raw.isAlive())try{report("ORIGINAL_HTTP_PROCESS_EXIT="+raw.exitValue());}catch(IllegalThreadStateException ignored){}}
    if(transport!=null)report("ORIGINAL_HTTP_TRANSPORT_STATE="+transport.failure());
  }
  private static String boundedLine(InputStream input,int limit)throws IOException{
    ByteArrayOutputStream bytes=new ByteArrayOutputStream();int value;
    while((value=input.read())!=-1){if(value=='\n')break;if(bytes.size()>=limit)throw new IOException("LINE_BOUND");bytes.write(value);}
    return value==-1&&bytes.size()==0?null:new String(bytes.toByteArray(),StandardCharsets.US_ASCII);
  }
  private static String hash(InputStream stream,int bound)throws Exception{
    MessageDigest hash=MessageDigest.getInstance("SHA-256");int total=0,n;byte[] block=new byte[8192];
    try(InputStream in=stream){while((n=in.read(block))!=-1){if((total+=n)>bound)throw new IOException("BODY_BOUND");hash.update(block,0,n);}}return hex(hash.digest());
  }
  private static String hex(byte[] bytes){StringBuilder s=new StringBuilder();for(byte b:bytes)s.append(String.format(Locale.ROOT,"%02x",b&255));return s.toString();}
  private void report(String line){if(!closed.get()){status.append(line).append('\n');text.setText(status.toString());}}
  private void deny(String reason){if(closed.get())return;report("ORIGINAL_HTTP_COMPONENT=DENY_"+reason);report("FORMAL_V139=BLOCKED");close();}
  private void close(){
    if(!closed.compareAndSet(false,true))return;
    // FD teardown may wait for a native pipe operation. Keep status/copy and
    // Activity lifecycle responsive while revoking the authenticated child.
    Thread cleanup=new Thread(()->{
      try{if(transport!=null)transport.close();}
      finally{try{if(intake!=null)intake.disconnected();}
        finally{try{if(raw!=null&&raw.isAlive())raw.destroyForcibly();}
          finally{if(pipes!=null)pipes.close();}}}
    },"original-http-revoke");cleanup.setDaemon(true);cleanup.start();
    if(deathLinked&&worker!=null)worker.getBinder().unlinkToDeath(workerDied,0);
    if(bound){try{unbindService(connection);}catch(RuntimeException ignored){}bound=false;}
  }
  @Override public void onDestroy(){close();super.onDestroy();}
}
