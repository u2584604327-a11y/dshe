package com.dsh.android.p50;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.system.Os;
import com.dsh.android.p134.P134RealArm64Gate;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p68.P68AndroidBinderIntake.WorkerPipes;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * P50 real ORIGINAL-v138 ARM64 Node *fixed synthetic control only* inside
 * original com.dsh.android isolated Service. Never production EngineManager.
 * Executable, args, environment, cwd, script and resources are all fixed.
 * No internet, root, arbitrary caller path, uploaded diagnostics or fallback.
 */
public final class P50OriginalNodeFixedChild {
  private static final String NODE="libdshnode_p21_exec.so";
  private static final String APK_SHA=
      "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5";
  private static final String NODE_SHA=
      "a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6";
  private static final String FIXED_JS=
      "process.stdout.write('UID='+process.getuid()+'\\nBOOT\\nREADY\\n');"
      +"process.stderr.write('P50-STDERR\\n');";
  private final Context context;
  private final Messenger host;
  private final String session;
  private final Object sendLock=new Object();
  private volatile java.lang.Process child;
  private volatile boolean aborted;
  private long sequence=0;
  private boolean started;
  private WorkerPipes modulePipes;
  private boolean freshConfig,httpServices,webMainTest;

  // Fixed supervisor diagnostics, never authority, paths or exception text.
  public static String failureStageName(int stage) {
    switch(stage){
      case 1:return "VERIFY_RUNTIME";
      case 2:return "LOAD_BOOTSTRAP";
      case 3:return "CREATE_CHILD";
      case 4:return "ATTACH_PIPES";
      case 5:return "WAIT_CHILD_EXIT";
      case 6:return "DRAIN_PIPES";
      default:return "UNSPECIFIED";
    }
  }

  /** Explicit permissionless sidecar only; never authorizes production P47. */
  public static P50OriginalNodeFixedChild originalDefaultConfig(Context context,
      Messenger authenticatedHost,String session,WorkerPipes authenticatedPipes) {
    if(context==null || authenticatedPipes==null ||
       !"com.dsh.p51.isolatedprobe".equals(context.getPackageName()))
      throw new SecurityException("P50_DEFAULT_CONFIG_SIDECAR_ONLY");
    P50OriginalNodeFixedChild result=new P50OriginalNodeFixedChild(context,authenticatedHost,session);
    result.modulePipes=authenticatedPipes;
    return result;
  }

  /** Fresh-profile runDumpConfig parity only. No production profile capability. */
  public static P50OriginalNodeFixedChild originalFreshConfig(Context context,
      Messenger authenticatedHost,String session,WorkerPipes pipes) {
    P50OriginalNodeFixedChild result=originalDefaultConfig(context,authenticatedHost,session,pipes);
    result.freshConfig=true;return result;
  }

  /** Distinct host-network test only. Never authorizes production P47. */
  public static P50OriginalNodeFixedChild originalHttpServices(Context context,
      Messenger authenticatedHost,String session,WorkerPipes pipes) {
    if(context==null||pipes==null||!"com.dsh.p51.networkprobe".equals(context.getPackageName()))
      throw new SecurityException("HTTP_COMPONENT_TEST_ONLY");
    P50OriginalNodeFixedChild result=new P50OriginalNodeFixedChild(context,authenticatedHost,session);
    result.modulePipes=pipes;result.httpServices=true;return result;
  }

  /** Full original runCli in the separate fresh-owner test package only.
   * Still no original EngineManager/P47/profile or production authority. */
  public static P50OriginalNodeFixedChild originalWebMainTest(Context context,
      Messenger authenticatedHost,String session,WorkerPipes pipes) {
    P50OriginalNodeFixedChild result=originalHttpServices(context,authenticatedHost,session,pipes);
    result.webMainTest=true;return result;
  }

  public P50OriginalNodeFixedChild(Context context, Messenger host, String session) {
    if(context==null || host==null || session==null ||
       !session.matches("[0-9a-f]{64}") || !Process.isIsolated())
      throw new IllegalArgumentException("P50_ISOLATED_AUTHENTICATED_SESSION_REQUIRED");
    this.context=context;this.host=host;this.session=session;
  }
  public synchronized void start(){
    if(started)throw new IllegalStateException("P50_ONE_SHOT_ONLY");
    started=true;
    emit(P48FixedIsolatedChild.HELLO,null,0);
    Thread t=new Thread(this::runFixedOriginalNode,"p50-original-verified-arm64-node");
    t.setDaemon(true);t.start();
  }
  public void stop(boolean force){
    aborted=true;
    java.lang.Process p=child;
    if(p!=null){if(force)p.destroyForcibly();else p.destroy();}
    if(modulePipes!=null)modulePipes.close();
  }
  private void emit(int kind,byte[] data,int code){
    emit(kind,data,code,0);
  }
  private void emit(int kind,byte[] data,int code,int failureStage){
    synchronized(sendLock){
      if(aborted)return;
      Bundle payload=new Bundle();
      payload.putString("session",session);
      payload.putLong("seq",kind==P48FixedIsolatedChild.HELLO?0:++sequence);
      if(data!=null)payload.putByteArray("data",data);
      if(kind==P48FixedIsolatedChild.EXIT)payload.putInt("exitCode",code);
      Message message=Message.obtain(null,kind);message.setData(payload);
      if(kind==P48FixedIsolatedChild.FAIL){
        message.arg1=failureStage;
        message.arg2=Integer.MIN_VALUE;
        java.lang.Process p=child;
        if(failureStage==6&&p!=null&&!p.isAlive())message.arg2=p.exitValue();
      }
      try{host.send(message);}
      catch(RemoteException lost){stop(true);}
    }
  }
  private static String sha256(File source) throws Exception {
    if(!source.isFile() || !source.canRead() ||
       source.length()<1000 || source.length()>128L*1024*1024)
      throw new SecurityException("P50_MISSING_OR_INVALID_ELF");
    MessageDigest digest=MessageDigest.getInstance("SHA-256");
    try(InputStream in=new FileInputStream(source)){
      byte[] bytes=new byte[32768];int n;
      while((n=in.read(bytes))>=0)if(n>0)digest.update(bytes,0,n);
    }
    StringBuilder builder=new StringBuilder(64);
    for(byte b:digest.digest())builder.append(String.format(Locale.ROOT,"%02x",b&255));
    return builder.toString();
  }
  private static String loadLock(InputStream input) throws IOException {
    try(InputStream in=input;ByteArrayOutputStream out=new ByteArrayOutputStream()){
      byte[] buffer=new byte[512];int n;
      while((n=in.read(buffer))!=-1) {
        if(n>16384-out.size())throw new IOException("P50_LOCK_TOO_LARGE");
        out.write(buffer,0,n);
      }
      return new String(out.toByteArray(),StandardCharsets.UTF_8);
    }
  }
  private static boolean safeAlias(String name){
    return name!=null && name.matches("lib[A-Za-z0-9_.+-]{1,70}\\.so")
        && !name.contains("..") && name.indexOf('/')<0;
  }
  private static void pipe(InputStream input,int what,
                           AtomicReference<String> failure,
                           P50OriginalNodeFixedChild owner) {
    try(InputStream in=input){
      int n;long total=0;byte[] buf=new byte[256];
      while((n=in.read(buf))!=-1){
        total+=n;
        if(total>2048){failure.compareAndSet(null,"P50_STREAM_EXCEEDED");return;}
        if(n>0)owner.emit(what,Arrays.copyOf(buf,n),0);
        if(owner.aborted)throw new IOException("P50_CANCELLED");
      }
    }catch(Exception e){failure.compareAndSet(null,"P50_PIPE_FAILURE");}
  }
  private void runFixedOriginalNode(){
    java.lang.Process node=null;
    android.os.IBinder.DeathRecipient hostDied=()->stop(true);
    boolean deathLinked=false;
    int failureStage=1;
    try{
      host.getBinder().linkToDeath(hostDied,0);deathLinked=true;
      // P134: x86_64 Google APIs Native Bridge advertises arm64-v8a in
      // SUPPORTED_ABIS. That is NOT evidence of an ARM64 kernel/process.
      // Reject translated guest architectures before any asset read/exec.
      if(!P134RealArm64Gate.allow(Process.isIsolated(),
            Build.VERSION.SDK_INT,Build.SUPPORTED_ABIS,Os.uname().machine))
        throw new SecurityException("P50_REQUIRES_REAL_ARM64_ISOLATED_ANDROID");
      if(context.checkSelfPermission(Manifest.permission.INTERNET)
           ==PackageManager.PERMISSION_GRANTED)
        throw new SecurityException("P50_WORKER_HAS_INTERNET_PERMISSION");
      File dir=new File(context.getApplicationInfo().nativeLibraryDir).getCanonicalFile();
      if(!dir.isDirectory())throw new IOException("P50_NO_INSTALLER_NATIVE_DIR");
      File executable=new File(dir,NODE).getCanonicalFile();
      if(!dir.equals(executable.getParentFile())||!executable.canExecute()||
         !NODE_SHA.equals(sha256(executable)))
        throw new SecurityException("P50_EXACT_NODE_ORIGIN_INVALID");

      JSONObject lock=new JSONObject(loadLock(
          context.getAssets().open("p49-original-node-lock.json")));
      if(!"P28_EXACT_V138_NODE_SHA_PIN".equals(lock.getString("gate")) ||
         !APK_SHA.equals(lock.getString("source_apk_sha256")) ||
         !NODE_SHA.equals(lock.getString("node_sha256")) ||
         !"NOT_TESTED_BUILD_ONLY".equals(lock.getString("runtime_node_execve")) ||
         !"BLOCKED".equals(lock.getString("release")))
        throw new SecurityException("P50_RUNTIME_LOCK_CHANGED");
      JSONArray libs=lock.getJSONArray("libs"), preloads=lock.getJSONArray("preload");
      if(libs.length()!=10||preloads.length()!=6)
        throw new SecurityException("P50_DEPENDENCY_COUNT_DRIFT");
      Set<String> names=new HashSet<>();
      for(int i=0;i<libs.length();i++){
        JSONObject entry=libs.getJSONObject(i);
        String alias=entry.getString("alias"),checksum=entry.getString("sha256");
        if(!safeAlias(alias) || !checksum.matches("[0-9a-f]{64}") ||
           !names.add(alias))
          throw new SecurityException("P50_LIBRARY_ALIAS_DRIFT");
        File f=new File(dir,alias).getCanonicalFile();
        if(!dir.equals(f.getParentFile()) || !checksum.equals(sha256(f)))
          throw new SecurityException("P50_LIBRARY_SHA_DRIFT");
      }
      StringBuilder preloadsEnv=new StringBuilder();
      Set<String> preloadSet=new HashSet<>();
      for(int i=0;i<preloads.length();i++){
        String alias=preloads.getString(i);
        if(!safeAlias(alias) || !names.contains(alias) ||
           !preloadSet.add(alias))throw new SecurityException("P50_PRELOAD_INVALID");
        if(i>0)preloadsEnv.append(':');
        preloadsEnv.append(new File(dir,alias).getAbsolutePath());
      }
      if(aborted)throw new IOException("P50_STOP_BEFORE_SPAWN");

      failureStage=2;
      String script=modulePipes==null?FIXED_JS:loadModuleBootstrap();
      ProcessBuilder pb=modulePipes==null?
          new ProcessBuilder(executable.getAbsolutePath(),"--no-warnings","--eval",script):
          new ProcessBuilder(executable.getAbsolutePath(),"--no-warnings","--input-type=module","--eval",script);
      if(httpServices){
        File addon=new File(dir,"libdsh_original_require_builtin.so").getCanonicalFile();
        if(!dir.equals(addon.getParentFile())||addon.length()!=91840||
            Os.sysconf(android.system.OsConstants._SC_PAGESIZE)!=4096||
            !"b69021cecbe48a62395b6a30c4975d17c4277ccb2429adada78dd74bc0fb0c44".equals(sha256(addon)))
          throw new SecurityException("P50_EXACT_ANDROID_ADDON_OR_PAGE_SIZE_INVALID");
        pb=new ProcessBuilder(executable.getAbsolutePath(),"--no-warnings","--permission","--allow-addons",
          "--allow-fs-read="+addon.getAbsolutePath(),"--allow-fs-read=/dsh-runtime","--allow-fs-read=/dsh-home",
          "--input-type=module","--eval",script);
      }
      pb.directory(new File("/"));
      Map<String,String> env=pb.environment();
      env.clear();
      env.put("PATH","/system/bin");
      env.put("HOME",modulePipes==null?"/":"/dsh-home");
      if(modulePipes!=null){env.put("DSH_HOME","/dsh-home");
        env.put("DSH_ORIGINAL_CONFIG_MODE",freshConfig?"fresh-config":"default");
        env.put("NODE_OPTIONS","--max-old-space-size=1024");}
      env.put("LD_LIBRARY_PATH",dir.getAbsolutePath());
      env.put("LD_PRELOAD",preloadsEnv.toString());
      failureStage=3;
      node=pb.start(); child=node;
      if(aborted){node.destroyForcibly();throw new IOException("P50_CANCELLED");}
      // P53: send on Binder only after actual original ARM64 Node
      // ProcessBuilder.start() returns successfully. This is not READY.
      emit(P48FixedIsolatedChild.CHILD_STARTED,null,0);

      if(modulePipes!=null) {
        failureStage=4;
        modulePipes.attach(node);
        failureStage=5;
        if(!node.waitFor(90,TimeUnit.SECONDS) || aborted)
          throw new IOException("P50_ORIGINAL_MODULE_TIMEOUT");
        failureStage=6;
        if(!modulePipes.finishAfterChildExit(5000))
          throw new IOException("P50_ORIGINAL_MODULE_PIPE_FAILURE");
        emit(P48FixedIsolatedChild.EXIT,null,node.exitValue());
        return;
      }

      final java.lang.Process running=node;
      AtomicReference<String> failure=new AtomicReference<>();
      Thread stdout=new Thread(()->pipe(running.getInputStream(),
          P48FixedIsolatedChild.STDOUT,failure,this),"p50-original-node-stdout");
      Thread stderr=new Thread(()->pipe(running.getErrorStream(),
          P48FixedIsolatedChild.STDERR,failure,this),"p50-original-node-stderr");
      stdout.start();stderr.start();
      boolean exited=node.waitFor(18,TimeUnit.SECONDS);
      if(!exited){node.destroyForcibly();failure.compareAndSet(null,"P50_TIMEOUT");}
      stdout.join(3500);stderr.join(3500);
      if(!exited||stdout.isAlive()||stderr.isAlive()||
         failure.get()!=null||aborted)
        throw new IOException("P50_NODE_STREAM_TIMEOUT_OR_CANCELLED");
      emit(P48FixedIsolatedChild.EXIT,null,node.exitValue());
    }catch(Exception | LinkageError failure) {
      // No raw exception string, environment, user data, or executable path.
      emit(P48FixedIsolatedChild.FAIL,null,125,modulePipes==null?0:failureStage);
    }finally {
      if(node!=null && node.isAlive())node.destroyForcibly();
      if(modulePipes!=null)modulePipes.close();
      if(deathLinked)host.getBinder().unlinkToDeath(hostDied,0);
      child=null;
    }
  }
  private String loadModuleBootstrap()throws Exception {
    byte[] bytes;
    try(InputStream input=context.getAssets().open(webMainTest?"engine-original-main.mjs":httpServices?"engine-http-services.mjs":"p50-original-modules.mjs");
        ByteArrayOutputStream output=new ByteArrayOutputStream()) {
      byte[] chunk=new byte[4096];int n;
      while((n=input.read(chunk))!=-1) {
        if(n>(webMainTest?131072:httpServices?65536:32768)-output.size())throw new IOException("P50_BOOTSTRAP_BOUND");
        output.write(chunk,0,n);
      }
      bytes=output.toByteArray();
    }
    StringBuilder hash=new StringBuilder(64);
    for(byte b:MessageDigest.getInstance("SHA-256").digest(bytes))
      hash.append(String.format(Locale.ROOT,"%02x",b&255));
    if(!(webMainTest?MAIN_TEST_BOOTSTRAP_SHA:httpServices?HTTP_BOOTSTRAP_SHA:MODULE_BOOTSTRAP_SHA).equals(hash.toString()))
      throw new SecurityException("P50_BOOTSTRAP_HASH_MISMATCH");
    return new String(bytes,StandardCharsets.UTF_8);
  }
  private static final String HTTP_BOOTSTRAP_SHA="c78ea5b631d5716d9cf3aa324613637f5a88919f0744058b382f4b8e503f30b1";
  private static final String MAIN_TEST_BOOTSTRAP_SHA="a6b4735816a82d1b7095763982333d6fbcff7cc3499e0865976e2578864b5359";
  private static final String MODULE_BOOTSTRAP_SHA="bc0c4c874e617016de0bd909c7c665795a7d6ff728e8245677f4e71074bbf140";
}
