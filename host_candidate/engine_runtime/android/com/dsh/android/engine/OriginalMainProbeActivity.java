package com.dsh.android.engine;
import android.app.Activity;import android.content.*;import android.os.*;import android.widget.*;
import com.dsh.p37.P37RemoteProcess;
import java.lang.Process;
import java.io.*;import java.nio.charset.StandardCharsets;import java.nio.file.*;import java.nio.file.attribute.*;import java.security.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;

/** Physical ARM64 original runCli + actual workspace/RPC/WS/restart test.
 * A separate package, fresh test-owned storage, never original DSH data or
 * the original EngineManager coroutine. No production READY assertion. */
public final class OriginalMainProbeActivity extends Activity {
  private final Handler main=new Handler(Looper.getMainLooper());private final AtomicBoolean closed=new AtomicBoolean();
  private final AtomicReference<String> stage=new AtomicReference<>("BIND"),transportFault=new AtomicReference<>("NONE/NONE");
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
    OriginalAndroidWebLaunch retiredLaunch=null;
    try{
      setStage("APK_IDENTITY");
      post("MAIN_TEST_INSTALLED_APK_SHA256="+installedApkSha256());
      checkReadyDiagnostics();
      post("MAIN_TEST_ORIGINAL_READY_REDACTION_AND_PRIVATE_URL=PASS");
      root=Files.createTempDirectory(getNoBackupFilesDir().toPath(),"original-main-test-",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      for(int generation=0;generation<2;generation++){
        if(closed.get())return;
        setStage("ORIGINAL_WORKSPACE_LAUNCH_PLAN");
        Integer portOption=generation==0?HttpProcessTransport.originalWebPortOption():Integer.valueOf(port);
        OriginalAndroidWebLaunch launch=OriginalAndroidWebLaunch.prepare(this,portOption);
        if(closed.get())return;setStage(generation==0?"FIRST_BIND":"RESTART_BIND");
        OriginalMainTestSession bound=new OriginalMainTestSession(this,
            sent->post("ORIGINAL_MAIN_RESOURCE_WIRE_BYTES_SENT="+sent));session=bound;bound.bind();
        P37RemoteProcess raw=bound.awaitChild();post("ORIGINAL_MAIN_AUTHENTICATED_ISOLATED_CHILD=PASS generation="+generation);
        try{
          try{bound.awaitChild();throw new IllegalStateException("MAIN_CHILD_REPLAY_ACCEPTED");}
          catch(IOException denied){require("MAIN_CHILD_CLAIM_DENIED".equals(denied.getMessage()),"MAIN_CHILD_REPLAY_RESULT");}
          post("ORIGINAL_MAIN_CHILD_HANDOFF_REPLAY=DENY generation="+generation);
          if(closed.get())return;
          setStage("OWNER_BRIDGE_ACTIVATION");
          DurableSessionSnapshot store=new DurableSessionSnapshot(root,owner);
          OriginalMainOwnerHandoff lease;
          try{lease=OriginalMainOwnerHandoff.offer(launch,bound,raw,store);}
          catch(IOException|RuntimeException denied){
            try{store.close();}catch(IOException release){denied.addSuppressed(release);}
            throw denied;
          }
          OriginalMainOwnerHandoff.VerifiedLaunch admitted;
          try(OriginalMainOwnerHandoff offer=lease){
            if(retiredLaunch!=null)expectOwnedStartDenied(retiredLaunch);
            Process launched=invokeOwnedStart(launch);
            admitted=offer.verifiedLaunch();
            transport=admitted.process;
            require(launched==admitted.process,"MAIN_OWNER_HANDOFF_EXACT_PROCESS");
            expectOwnedStartDenied(launch);
          }
          HttpProcessTransport active=admitted.process;
          if(closed.get())return;
          require(active.getErrorStream().read()==-1,"MAIN_MERGED_ERROR_STREAM");
          OriginalMainStartup startup=admitted.startup;port=startup.port();
          String cookie=admitted.cookie;
          if(generation==1)startup.verifyRetiredCredentials(oldToken,oldCookie);
          post("ORIGINAL_MAIN_RESOURCE_SOURCE=VERIFIED_COMPLETE");
          post("ORIGINAL_MAIN_RUNCLI=INVOKED");
          post("ORIGINAL_MAIN_BROWSER_PANE_CLIENT_BYTES=PASS generation="+generation);
          post("ORIGINAL_MAIN_MOBILE_CLIENT_BYTES_AND_PRIVILEGE_FENCE=PASS generation="+generation);
          post("ORIGINAL_MAIN_OWNER_BOUND_BRIDGE=PASS generation="+generation);
          InputStream admittedOutput=active.getInputStream();
          require(OriginalMainStartup.permitsVerifiedAnnouncement(active,OriginalMainHttpChecks.line(admittedOutput)),"MAIN_VERIFIED_STDOUT_HANDOFF");
          Thread stdout=new Thread(()->{
            try(InputStream input=admittedOutput){byte[] block=new byte[4096];while(input.read(block)!=-1){}}
            catch(IOException ignored){}
          },"original-main-verified-stdout");
          stdout.setDaemon(true);
          stdout.start();
          post("ORIGINAL_MAIN_PROCESS_MERGED_STDERR=PASS generation="+generation);
          post("ORIGINAL_MAIN_OWNED_READY_PROOF=PASS generation="+generation);
          OriginalMainHttpChecks.verifyDefaultWorkspace(port,cookie);
          post("ORIGINAL_MAIN_ORIGINAL_WORKSPACE_OVERLAY=PASS generation="+generation);
          setStage("ORIGINAL_WORKSPACE_RPC");String body="{\"type\":\"client-request\",\"rpcId\":\"main-test\",\"method\":\"workspace/create\",\"payload\":{\"args\":{\"request\":{\"path\":\"/dsh-workspace\"}}}}";
          OriginalMainHttpChecks.Reply reply=OriginalMainHttpChecks.request(port,"/api/workspace/create",cookie,body);String value=new String(reply.body,StandardCharsets.UTF_8).replaceAll("\\s+","");
          require(reply.status==200&&value.contains("\"ok\":true")&&value.contains("\"created\":"+(generation==0))&&value.contains("/dsh-workspace"),"MAIN_WORKSPACE_RESTORE");
          setStage("ORIGINAL_WORKSPACE_WEBSOCKET");OriginalMainHttpChecks.workspaceStream(port,cookie);
          setStage("HOST_FENCE");OriginalMainHttpChecks.hostFence(port,cookie);
          setStage("STOP_AND_DISPOSE");active.destroy();require(active.waitFor(8,TimeUnit.SECONDS)&&active.exitValue()==0&&raw.terminalReason()==P37RemoteProcess.TerminalReason.REMOTE_EXIT,"MAIN_ACTUAL_EXIT");active.close();require(active.awaitClosed(5,TimeUnit.SECONDS)&&active.failure().equals("NONE/NONE"),"MAIN_OWNER_RELEASE");
          oldCookie=cookie;oldToken=startup.privateTarget();retiredLaunch=launch;transport=null;
          post("ORIGINAL_MAIN_AUTH_FRONTEND_WORKSPACE_RPC_AND_WS=PASS generation="+generation);post("ORIGINAL_MAIN_ACTUAL_CHILD_EXIT=0 generation="+generation);
        }finally{HttpProcessTransport current=transport;if(current!=null){current.close();current.awaitClosed(5,TimeUnit.SECONDS);transportFault.set(current.failure());transport=null;}bound.close();session=null;}
      }
      post("ORIGINAL_MAIN_WORKSPACE_DURABLE_NODE_RESTART_AND_OLD_TOKEN_REVOCATION=PASS");post("ORIGINAL_MAIN_ANDROID_SSE_AND_MODEL_RESPONSE=NOT_TESTED");
      post("ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED");post("ORIGINAL_DSH_HTTP_READY=NOT_WIRED");post("FORMAL_V139=BLOCKED");main.post(this::close);
    }catch(Exception|LinkageError denied){
      final String fixed=denied.getMessage()!=null&&denied.getMessage().matches("[A-Z0-9_]{1,64}")?denied.getMessage():"OTHER";
      main.post(()->{report("ORIGINAL_MAIN_FIXED_FAILURE_CODE="+fixed);report("ORIGINAL_MAIN_TRANSPORT_STATE="+transportFault.get());deny(stage.get());});
    }
    finally{if(root!=null)try{Files.deleteIfExists(root.resolve("snapshot.bin"));Files.deleteIfExists(root.resolve("owner.lock"));Files.delete(root);}catch(IOException ignored){}}
  }
  private String installedApkSha256()throws IOException,NoSuchAlgorithmException{
    MessageDigest digest=MessageDigest.getInstance("SHA-256");
    try(InputStream input=new FileInputStream(getApplicationInfo().sourceDir)){
      byte[] block=new byte[65536];
      for(int length;(length=input.read(block))!=-1;){
        if(closed.get())throw new InterruptedIOException("MAIN_TEST_APK_IDENTITY_CANCELLED");
        digest.update(block,0,length);
      }
    }
    return hex(digest.digest());
  }
  private Process invokeOwnedStart(OriginalAndroidWebLaunch launch)throws ReflectiveOperationException,IOException{
    Class<?> bridge=Class.forName("com.dsh.android.engine.OriginalStartupDiagnostics",true,getClassLoader());
    try{return (Process)bridge.getMethod("startOwned",ProcessBuilder.class,launch.engine.getClass())
        .invoke(null,launch.original,launch.engine);}
    catch(java.lang.reflect.InvocationTargetException denied){
      if(denied.getCause() instanceof IOException)throw (IOException)denied.getCause();
      throw denied;
    }
  }
  private void expectOwnedStartDenied(OriginalAndroidWebLaunch launch)throws Exception{
    try{invokeOwnedStart(launch);throw new IOException("MAIN_OWNER_HANDOFF_REPLAY_ACCEPTED");}
    catch(IOException denied){
      require("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK"
          .equals(denied.getMessage()),"MAIN_OWNER_HANDOFF_REPLAY_RESULT");
    }
  }
  private void checkReadyDiagnostics()throws ReflectiveOperationException,IOException{
    Class<?> ready=Class.forName("com.dsh.android.EngineManager$State$Ready",true,getClassLoader());
    String sample="http://127.0.0.1:34567/?token=diagnostic-check";
    Object state=ready.getConstructor(String.class).newInstance(sample);
    require(sample.equals(ready.getMethod("getUrl").invoke(state))&&
        "Ready(url=[launch credential withheld])".equals(state.toString()),"MAIN_TEST_ORIGINAL_READY_DIAGNOSTICS");
  }
  private static void require(boolean value,String code)throws IOException{if(!value)throw new IOException(code);}
  private static String hex(byte[] bytes){StringBuilder result=new StringBuilder();for(byte b:bytes)result.append(String.format(Locale.ROOT,"%02x",b&255));return result.toString();}
  private static String randomId(){byte[] random=new byte[32];new SecureRandom().nextBytes(random);String id=hex(random);Arrays.fill(random,(byte)0);return id;}
  private void report(String line){if(!closed.get()){status.append(line).append('\n');text.setText(status.toString());}}
  private void deny(String fixed){if(closed.get())return;report("ORIGINAL_MAIN_TEST=DENY_"+fixed);report("FORMAL_V139=BLOCKED");close();}
  private void close(){if(!closed.compareAndSet(false,true))return;Thread cleanup=new Thread(()->{try{HttpProcessTransport active=transport;if(active!=null)active.close();}finally{OriginalMainTestSession active=session;if(active!=null)active.close();}},"original-main-owner-revoke");cleanup.setDaemon(true);cleanup.start();}
  @Override public void onDestroy(){close();super.onDestroy();}
}
