package com.dsh.p22.ziplink;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.util.Log;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Tests isolatedProcess execve + Bionic DT_NEEDED .so.3 from page-aligned APK.
 * Not a real DSH Node binary and not a proof of ARM64 behavior.
 */
public final class P22ZipLinkWorker extends Service {
  private static final String TAG="DSH_P22_ZIPLINK";
  private final Messenger receive=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message request) {
      if(request.what!=1 || request.replyTo==null || !Process.isIsolated())return;
      if(request.sendingUid!=getApplicationInfo().uid)return;
      final Messenger respond=request.replyTo;
      new Thread(()->{
        boolean executable=false;
        boolean verifiedZipLink=false;
        String stage="CHECK_INSTALLED_EXECUTABLE";
        java.lang.Process child=null;
        try {
          final String libDir=getApplicationInfo().nativeLibraryDir;
          final File executableFile=new File(libDir,"libp22probe_exec.so");
          executable=executableFile.isFile() && executableFile.canExecute();
          if(!executable)throw new IllegalStateException("missing installer executable");
          stage="ENSURE_VERSIONED_LIB_NOT_INSTALLED";
          if(new File(libDir,"libp22version.so.3").exists())
            throw new IllegalStateException("versioned library extracted; not a ZIP test");
          stage="EXEC_PIE_WITH_APK_ZIP_LIBRARY_SEARCH";
          ProcessBuilder process=new ProcessBuilder(executableFile.getAbsolutePath(),"--version");
          process.redirectErrorStream(true);
          process.directory(new File("/"));
          Map<String,String> env=process.environment();
          env.clear();
          env.put("PATH","/system/bin");
          env.put("HOME","/");
          env.put("LD_LIBRARY_PATH",getApplicationInfo().sourceDir+"!/lib/x86_64");
          child=process.start();
          stage="READ_SHORT_OUTPUT_AND_WAIT";
          if(!child.waitFor(10,TimeUnit.SECONDS))
            throw new IllegalStateException("child timeout");
          int status=child.exitValue();
          InputStream output=child.getInputStream();
          byte[] bytes=new byte[256];int n=output.read(bytes);
          String stdout=n<0?"":new String(bytes,0,n,StandardCharsets.UTF_8).trim();
          verifiedZipLink=(status==0 && stdout.equals("P22_VERSIONED_ZIP_DEPENDENCY_OK:22035"));
          if(!verifiedZipLink)
            Log.e(TAG,"P22_CHILD_EXIT_OR_OUTPUT_MISMATCH=FAIL");
        }catch(Exception error){
          Log.e(TAG,"P22_STAGE_"+stage+"="+error.getClass().getSimpleName());
        }finally{
          if(child!=null && child.isAlive())child.destroyForcibly();
        }
        Bundle result=new Bundle();
        result.putInt("uid",Process.myUid());
        result.putBoolean("isolated",Process.isIsolated());
        result.putBoolean("apkExec",executable);
        result.putBoolean("versionedLibrary",verifiedZipLink);
        Message response=Message.obtain(null,1);
        response.setData(result);
        try{respond.send(response);}catch(Exception ignored){}
      },"p22-versioned-linker-probe").start();
    }
  });
  @Override public IBinder onBind(Intent intent){
    if(!Process.isIsolated())throw new SecurityException("isolated worker required");
    return receive.getBinder();
  }
}
