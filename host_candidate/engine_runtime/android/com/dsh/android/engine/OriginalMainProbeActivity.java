package com.dsh.android.engine;
import android.app.Activity;import android.content.*;import android.os.*;import android.widget.*;
import com.dsh.android.p50.P50ModuleStream;import com.dsh.p37.P37RemoteProcess;
import java.io.*;import java.net.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.nio.file.attribute.*;import java.security.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;

/** Physical ARM64 original runCli + actual workspace/RPC/WS/restart test.
 * A separate package, fresh test-owned storage, never original DSH data or
 * the original EngineManager coroutine. No production READY assertion. */
public final class OriginalMainProbeActivity extends Activity {
  private final Handler main=new Handler(Looper.getMainLooper());private final AtomicBoolean closed=new AtomicBoolean();
  private final AtomicReference<String> stage=new AtomicReference<>("BIND"),childError=new AtomicReference<>("NONE"),transportFault=new AtomicReference<>("NONE/NONE");
  private final StringBuilder status=new StringBuilder();private TextView text;
  private volatile OriginalMainTestSession session;private volatile HttpProcessTransport transport;
  @Override public void onCreate(Bundle saved){
    super.onCreate(saved);text=new TextView(this);text.setTextSize(13);text.setPadding(16,16,16,16);
    text.setOnLongClickListener(view->{((android.content.ClipboardManager)getSystemService(CLIPBOARD_SERVICE)).setPrimaryClip(ClipData.newPlainText("Original main test status",status.toString()));return true;});
    ScrollView scroll=new ScrollView(this);scroll.addView(text);setContentView(scroll);
    if(Build.VERSION.SDK_INT<35||!"com.dsh.p51.networkprobe".equals(getPackageName())||android.os.Process.isIsolated()||
        checkSelfPermission("android.permission.INTERNET")!=android.content.pm.PackageManager.PERMISSION_GRANTED){deny("TEST_PACKAGE_OR_PERMISSION");return;}
    report("MAIN_TEST_SEPARATE_PACKAGE_NOT_ORIGINAL_DSH=YES");report("MAIN_TEST_ORIGINAL_DSH_DATA=UNTOUCHED");report("MAIN_TEST_FRESH_OWNER_ONLY=YES");
    report("MAIN_TEST_LONG_PRESS_COPY=YES");report("MAIN_TEST_DEVICE_PAGE_SIZE="+android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE));
    report("ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED");report("ORIGINAL_DSH_HTTP_READY=NOT_WIRED");
    Thread task=new Thread(this::verify,"original-main-fresh-owner-acceptance");task.setDaemon(true);task.start();
    main.postDelayed(()->deny("DEADLINE_"+stage.get()),240000);
  }
  private void setStage(String value){stage.set(value);post("ORIGINAL_MAIN_TEST_STAGE="+value);}
  private void post(String value){main.post(()->report(value));}
  private void verify(){
    Path root=null;String owner=randomId(),oldCookie=null,oldToken=null;int port=0;
    try{
      root=Files.createTempDirectory(getNoBackupFilesDir().toPath(),"original-main-test-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      for(int generation=0;generation<2;generation++){
        if(closed.get())return;setStage(generation==0?"FIRST_BIND":"RESTART_BIND");
        OriginalMainTestSession bound=new OriginalMainTestSession(this);session=bound;bound.bind();
        P37RemoteProcess raw=bound.awaitChild();post("ORIGINAL_MAIN_AUTHENTICATED_ISOLATED_CHILD=PASS generation="+generation);
        try{
          setStage("RESOURCE_TRANSFER");OutputStream resource=new FilterOutputStream(raw.getOutputStream()){
            long sent,next=32L*1024*1024;
            @Override public void write(int value)throws IOException{out.write(value);advanced(1);}
            @Override public void write(byte[] bytes,int offset,int length)throws IOException{out.write(bytes,offset,length);advanced(length);}
            void advanced(int count){sent+=count;if(sent>=next){next=sent+32L*1024*1024;post("ORIGINAL_MAIN_RESOURCE_WIRE_BYTES_SENT="+sent);}}
          };
          try(InputStream original=getAssets().open("engine.bin")){P50ModuleStream.writeOriginalForService(original,resource);}
          post("ORIGINAL_MAIN_RESOURCE_SOURCE=VERIFIED_COMPLETE");if(closed.get())return;
          setStage("OWNED_STORAGE_AND_MAIN");DurableSessionSnapshot store=new DurableSessionSnapshot(root,owner);
          HttpProcessTransport active;
          try{active=new HttpProcessTransport(raw,bound.session,bound.epoch,port,false,store);}catch(Exception bad){store.close();throw bad;}
          transport=active;if(closed.get()){active.close();return;}
          BlockingQueue<String> output=new ArrayBlockingQueue<>(96);
          Thread stdout=new Thread(()->{try{String row;int total=0;while((row=OriginalMainHttpChecks.line(active.getInputStream()))!=null){if((total+=row.length())>65536||!output.offer(row))throw new IOException("MAIN_LOG_BOUND");}}catch(Exception bad){output.offer("MAIN_LOG_FAILURE");}},"original-main-private-stdout");stdout.setDaemon(true);stdout.start();
          Thread stderr=new Thread(()->{try{String row;int total=0;while((row=OriginalMainHttpChecks.line(active.getErrorStream()))!=null){if((total+=row.length())>65536)break;if(row.matches("ORIGINAL_MAIN_DENY=[A-Z0-9_]{1,64}"))childError.set(row.substring(row.indexOf('=')+1));}}catch(Exception ignored){}},"original-main-fixed-diagnostics");stderr.setDaemon(true);stderr.start();
          if(!active.awaitListening(15,TimeUnit.SECONDS))throw new IOException("MAIN_LISTEN");port=active.port();
          long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);String target=null;boolean returned=false;
          while(target==null||!returned){long remaining=deadline-System.nanoTime();if(remaining<=0)throw new IOException("MAIN_STARTUP_OUTPUT");String row=output.poll(remaining,TimeUnit.NANOSECONDS);if(row==null||row.equals("MAIN_LOG_FAILURE"))throw new IOException("MAIN_OUTPUT_MISSING");
            if(row.startsWith("dsh web: http://127.0.0.1:")){URL url=new URL(row.substring(9));if(url.getPort()!=port||!"127.0.0.1".equals(url.getHost())||!"/".equals(url.getPath())||url.getUserInfo()!=null||url.getRef()!=null||url.getQuery()==null||!url.getQuery().matches("token=[A-Za-z0-9_-]{43}"))throw new IOException("MAIN_PRIVATE_URL");target=url.getFile();}
            if(row.equals("ORIGINAL_MAIN_ENTRY_RETURNED_NOT_READY_ATTESTATION"))returned=true;
          }
          post("ORIGINAL_MAIN_RUNCLI=INVOKED");setStage("AUTHENTICATION");
          require(OriginalMainHttpChecks.request(port,"/",null,null).status==401,"MAIN_UNAUTHENTICATED");
          if(generation==1){require(OriginalMainHttpChecks.request(port,"/",oldCookie,null).status==401,"MAIN_OLD_COOKIE");require(OriginalMainHttpChecks.request(port,oldToken,null,null).status==401,"MAIN_OLD_TOKEN");}
          OriginalMainHttpChecks.Reply login=OriginalMainHttpChecks.request(port,target,null,null);
          require(login.status==303&&login.cookie!=null&&login.cookie.contains("HttpOnly")&&login.cookie.contains("SameSite=Strict"),"MAIN_LOGIN");String cookie=login.cookie.split(";")[0];
          setStage("FRONTEND");OriginalMainHttpChecks.Reply frontend=OriginalMainHttpChecks.request(port,"/",cookie,null);require(frontend.status==200,"MAIN_FRONTEND");
          java.util.regex.Matcher script=java.util.regex.Pattern.compile("src=\"([.]/assets/[^\"]+[.]js)\"").matcher(new String(frontend.body,StandardCharsets.UTF_8));require(script.find(),"MAIN_FRONTEND_SCRIPT");
          OriginalMainHttpChecks.Reply js=OriginalMainHttpChecks.request(port,script.group(1).substring(1),null,null);require(js.status==200&&"4bc914bfbb6adbdd63953a29f63835eb7127defd2a973149d64cdab489f1a9a5".equals(hash(js.body)),"MAIN_ORIGINAL_JS_BYTES");
          setStage("ORIGINAL_WORKSPACE_RPC");String body="{\"type\":\"client-request\",\"rpcId\":\"main-test\",\"method\":\"workspace/create\",\"payload\":{\"args\":{\"request\":{\"path\":\"/dsh-workspace\"}}}}";
          OriginalMainHttpChecks.Reply reply=OriginalMainHttpChecks.request(port,"/api/workspace/create",cookie,body);String value=new String(reply.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
          require(reply.status==200&&value.contains("\"ok\":true")&&value.contains("\"created\":"+(generation==0))&&value.contains("/dsh-workspace"),"MAIN_WORKSPACE_RESTORE");
          setStage("ORIGINAL_WORKSPACE_WEBSOCKET");OriginalMainHttpChecks.workspaceStream(port,cookie);
          setStage("HOST_FENCE");OriginalMainHttpChecks.hostFence(port,cookie);
          setStage("STOP_AND_DISPOSE");active.destroy();require(active.waitFor(8,TimeUnit.SECONDS)&&active.exitValue()==0&&raw.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT,"MAIN_ACTUAL_EXIT");active.close();require(active.awaitClosed(5,TimeUnit.SECONDS)&&active.failure().equals("NONE/NONE"),"MAIN_OWNER_RELEASE");
          oldCookie=cookie;oldToken=target;transport=null;
          post("ORIGINAL_MAIN_AUTH_FRONTEND_WORKSPACE_RPC_AND_WS=PASS generation="+generation);post("ORIGINAL_MAIN_ACTUAL_CHILD_EXIT=0 generation="+generation);
        }finally{HttpProcessTransport current=transport;if(current!=null){current.close();current.awaitClosed(5,TimeUnit.SECONDS);transportFault.set(current.failure());transport=null;}bound.close();session=null;}
      }
      post("ORIGINAL_MAIN_WORKSPACE_DURABLE_NODE_RESTART_AND_OLD_TOKEN_REVOCATION=PASS");post("ORIGINAL_MAIN_ANDROID_SSE_AND_MODEL_RESPONSE=NOT_TESTED");
      post("ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED");post("ORIGINAL_DSH_HTTP_READY=NOT_WIRED");post("FORMAL_V139=BLOCKED");main.post(this::close);
    }catch(Exception|LinkageError denied){
      final String fixed=denied.getMessage()!=null&&denied.getMessage().matches("[A-Z0-9_]{1,64}")?denied.getMessage():"OTHER";
      main.post(()->{report("ORIGINAL_MAIN_FIXED_CHILD_ERROR="+childError.get());report("ORIGINAL_MAIN_FIXED_FAILURE_CODE="+fixed);report("ORIGINAL_MAIN_TRANSPORT_STATE="+transportFault.get());deny(stage.get());});
    }
    finally{if(root!=null)try{Files.deleteIfExists(root.resolve("snapshot.bin"));Files.deleteIfExists(root.resolve("owner.lock"));Files.delete(root);}catch(IOException ignored){}}
  }
  private static void require(boolean value,String code)throws IOException{if(!value)throw new IOException(code);}
  private static String hash(byte[] bytes)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
  private static String hex(byte[] bytes){StringBuilder result=new StringBuilder();for(byte b:bytes)result.append(String.format(Locale.ROOT,"%02x",b&255));return result.toString();}
  private static String randomId(){byte[] random=new byte[32];new SecureRandom().nextBytes(random);String id=hex(random);Arrays.fill(random,(byte)0);return id;}
  private void report(String line){if(!closed.get()){status.append(line).append('\n');text.setText(status.toString());}}
  private void deny(String fixed){if(closed.get())return;report("ORIGINAL_MAIN_TEST=DENY_"+fixed);report("FORMAL_V139=BLOCKED");close();}
  private void close(){if(!closed.compareAndSet(false,true))return;Thread cleanup=new Thread(()->{try{HttpProcessTransport active=transport;if(active!=null)active.close();}finally{OriginalMainTestSession active=session;if(active!=null)active.close();}},"original-main-owner-revoke");cleanup.setDaemon(true);cleanup.start();}
  @Override public void onDestroy(){close();super.onDestroy();}
}
