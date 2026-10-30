package com.dsh.android.p43;
import android.app.Activity;
import android.content.*;
import android.os.*;
import android.widget.TextView;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import com.dsh.android.p48.P48HostProcessProbe;
import com.dsh.p37.P37RemoteProcess;

/**
 * P43 temporary exported test entry exists ONLY in the throwaway emulator APK.
 * It MUST NOT be present in any user-release build.
 */
public final class P43ProbeActivity extends Activity {
  private final Handler main=new Handler(Looper.getMainLooper());
  private final StringBuilder status=new StringBuilder();
  private String session;
  private final P44VirtualDeviceProfile simulatedProfile=P44VirtualDeviceProfile.syntheticDemo();
  private static final byte[] P45_SYNTHETIC=
      "P45_SYNTHETIC_PRIVATE_ASSET_V1".getBytes(StandardCharsets.UTF_8);
  private static String sha256(byte[] input) {
    try {
      byte[] b=MessageDigest.getInstance("SHA-256").digest(input);
      StringBuilder s=new StringBuilder(64);
      for(byte v:b)s.append(String.format(Locale.ROOT,"%02x",v&255));
      return s.toString();
    }catch(Exception e){throw new IllegalStateException("HASH_UNAVAILABLE",e);}
  }
  private TextView label;
  private boolean bound,received,failed;
  private Messenger remote;
  private P48HostProcessProbe p48;
  private void log(String msg) {
    android.util.Log.i("P43_HOST_BINDER",msg);
    if(label!=null)label.setText(status.append(msg).append('\n').toString());
  }
  private void fail(String why){
    if(received||failed)return;
    failed=true;
    log("P43_EMBEDDED_ISOLATED_SERVICE_FAIL="+why);
  }
  private final Messenger replies=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message m){
      if(received||failed)return;
      if(m.what!=P43IsolatedWorker.HELLO ||
         !android.os.Process.isIsolatedUid(m.sendingUid) ||
         m.sendingUid==android.os.Process.myUid() ||
         !session.equals(m.getData().getString("session"))) {
        fail("UID_OR_SESSION_INVALID");return;
      }
      final Bundle response;
      try {response=m.getData();} catch(RuntimeException malformed) {
        fail("INVALID_PROFILE_REPLY");return;
      }
      if(!simulatedProfile.fingerprint().equals(response.getString("p44_profile_hash")) ||
         response.getBoolean("p44_is_real_virtual_machine",true) ||
         response.getBoolean("p44_hardware_identity_changed",true)) {
        fail("PROFILE_TAMPER_OR_UNAUTHORIZED_CLAIM");return;
      }
      if(!sha256(P45_SYNTHETIC).equals(response.getString("p45_asset_sha256")) ||
         response.getInt("p45_asset_size",-1)!=P45_SYNTHETIC.length ||
         response.getBoolean("p45_path_transferred",true) ||
         response.getBoolean("p45_root_used",true)) {
        fail("ASSET_FD_HASH_OR_SIZE_OR_PRIVILEGE_CLAIM_INVALID");return;
      }
      String expectedP46=P46ResourceBundle.fromFixture(
          P46FixtureData.bytes(0),P46FixtureData.bytes(1)).fingerprint();
      if(!expectedP46.equals(response.getString("p46_bundle_sha256")) ||
         response.getInt("p46_verified_parts",-1)!=P46ResourceBundle.COUNT ||
         response.getBoolean("p46_executed_any_script",true)) {
        fail("P46_CONTENT_ADDRESSED_BUNDLE_REJECTED");return;
      }
      received=true;
      log("P46_ORIGINAL_DSH_CONTENT_ADDRESSED_BUNDLE_FD=PASS");
      log("P46_TWO_FIXTURES_HASH_AND_BYTE_BOUNDS=PASS");
      log("P46_REAL_NODE_SCRIPT_EXECUTED=NO");
      log("P46_PRODUCTION_SCRIPT_PACKAGE_BROKER=NOT_IMPLEMENTED");
      log("P45_ORIGINAL_DSH_HOST_PRIVATE_ASSET_FD_TO_ISOLATED_WORKER=PASS");
      log("P45_BOUNDED_SYNTHETIC_ASSET_SHA256=PASS");
      log("P45_ROOT_REQUIRED=NO");
      log("P45_HOST_PATH_SHARED=NO");
      log("P45_PRODUCTION_ENGINE_SCRIPT_BROKER=NOT_IMPLEMENTED");
      log("P44_ORIGINAL_DSH_PROFILE_TO_ISOLATED_WORKER=PASS");
      log("P44_HOST_SELECTED_VIRTUAL_PROFILE_HASH_VALIDATED=PASS");
      log("P44_ACTUAL_SYSTEM_VM=NO");
      log("P44_REAL_DEVICE_IDENTITY_MODIFIED=NO");
      log("P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS");
      log("P43_ORIGINAL_DSH_APPLICATION_AND_ISOLATED_SERVICE_BOUND=PASS");
      log("P43_REAL_NODE_IN_ORIGINAL_ENGINE=NO");
      log("P43_V139_RELEASE=BLOCKED");
      if(remote!=null && p48==null) {
        // Only a *real* ARM64 test device with the P49 exact Node lock
        // opts into P50; x86 CI continues the P48 positive system-UID probe.
        boolean useExactNode=false;
        for(String abi:Build.SUPPORTED_ABIS)
          if("arm64-v8a".equals(abi))useExactNode=true;
        if(useExactNode){
          try(InputStream lock=getAssets().open("p49-original-node-lock.json")){
            useExactNode=lock.read()!=-1;
          }catch(IOException missing){useExactNode=false;}
        }
        final boolean p50Enabled=useExactNode;
        p48=new P48HostProcessProbe(remote,session,new P48HostProcessProbe.Listener(){
          @Override public void report(String line){log(line);}
          @Override public void fail(String code){
            log("P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_"+code);
          }
        },p50Enabled,(process,isolatedUid)->{
          if(!(process instanceof P37RemoteProcess) ||
             !android.os.Process.isIsolatedUid(isolatedUid) ||
             !process.isAlive() ||
             process.getInputStream()==null ||
             process.getErrorStream()==null)
            throw new IllegalStateException("P52_AUTHENTICATED_PROXY_BAD_TYPE_OR_UID");
          log("P53_P37_PROCESS_PROXY_AFTER_REAL_CHILD_START_ACK=PASS");
          log("P53_CHILD_START_ACK_IS_NOT_ENGINE_READY=YES");
          log("P52_LIVE_P37_JAVA_PROCESS_FROM_ISOLATED_BINDER=PASS");
          log("P52_PRODUCTION_ENGINEMANAGER_PROCESS_HANDOFF=NOT_WIRED");
          log("P52_BINDER_HELLO_IS_EXECVE_READY=NO");
        },true); // P68 test-only Binder handoff, not production EngineManager.
        log(p50Enabled?
            "P50_EXACT_ORIGINAL_NODE_TEST_REQUESTED=YES":
            "P50_X86_OR_MISSING_LOCK_ORIGINAL_NODE_NOT_REQUESTED=YES");
        p48.start();
      }
    }
  });
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      remote=new Messenger(binder);
      Message m=Message.obtain(null,P43IsolatedWorker.INIT);
      Bundle b=new Bundle();b.putString("session",session);
      b.putString("p44_profile",simulatedProfile.wire());
      ParcelFileDescriptor assetFd=null;File syntheticFile=null;
      P46HostBroker.Lease p46Lease=null;
      try {
        syntheticFile=File.createTempFile("p45-synthetic-", ".bin", getCacheDir());
        try(FileOutputStream output=new FileOutputStream(syntheticFile)) {
          output.write(P45_SYNTHETIC);
          output.getFD().sync();
        }
        // Only the already-open O_RDONLY descriptor crosses Binder; unlink
        // filename before transfer so the worker never needs its host path.
        assetFd=ParcelFileDescriptor.open(syntheticFile,ParcelFileDescriptor.MODE_READ_ONLY);
        if(!syntheticFile.delete())throw new IOException("UNLINK_FAILED");
        b.putParcelable("p45_readonly_fd",assetFd);
        b.putInt("p45_max_bytes",64);
        p46Lease=P46HostBroker.attachFixture(P43ProbeActivity.this,b);
        m.replyTo=replies;m.setData(b);
        remote.send(m);
      }catch(Exception failure) {
        fail("SYNTHETIC_FD_BROKER_FAILED");
      }finally{
        if(p46Lease!=null)p46Lease.close();
        if(assetFd!=null)try{assetFd.close();}catch(IOException ignored){}
        if(syntheticFile!=null)syntheticFile.delete();
      }
    }
    @Override public void onServiceDisconnected(ComponentName n){fail("SERVICE_DISCONNECTED");}
    @Override public void onBindingDied(ComponentName n){fail("BINDING_DIED");}
    @Override public void onNullBinding(ComponentName n){fail("NULL_BINDING");}
  };
  /**
   * P47: invoke the SAME P40 bridge class in the patched main DEX that the
   * real EngineManager main coroutine references. This test-only Activity
   * cannot prove the full production coroutine path or Node functionality.
   */
  private boolean assertExactBridgeFailClosed() {
    File canary=new File(getCacheDir(),"p47-no-host-fallback-canary");
    if(canary.exists() && !canary.delete())return false;
    ProcessBuilder candidate=new ProcessBuilder(
        "/system/bin/sh","-c","echo P47_UNAUTHORIZED > "+canary.getAbsolutePath());
    candidate.directory(getCacheDir());
    candidate.redirectErrorStream(true);
    try {
      Class<?> klass=Class.forName("com.dsh.android.p40.P40ProcessBridge");
      Method method=klass.getDeclaredMethod("start",ProcessBuilder.class);
      // Under no circumstance should this return a host Process.
      Object unexpectedlyStarted=method.invoke(null,candidate);
      if(unexpectedlyStarted instanceof java.lang.Process)
        ((java.lang.Process)unexpectedlyStarted).destroyForcibly();
      return false;
    }catch(InvocationTargetException result) {
      Throwable cause=result.getCause();
      if(!(cause instanceof IOException) ||
         !"P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK".equals(cause.getMessage()))
        return false;
    }catch(Exception invalid){return false;}
    if(canary.exists()){canary.delete();return false;}
    log("P47_REAL_ORIGINAL_MAIN_DEX_ENGINE_BRIDGE_DENIES_HOST_START=PASS");
    log("P47_NO_HOST_PROCESSBUILDER_FALLBACK=PASS");
    log("P47_PRODUCTION_NODE_ENGINE_RUNNING=NO");
    return true;
  }
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    label=new TextView(this);label.setTextSize(16);
    label.setTextIsSelectable(true);setContentView(label);
    if("com.dsh.p51.isolatedprobe".equals(getPackageName())) {
      log("P51_SIDE_BY_SIDE_TEST_NOT_ORIGINAL_DSH=YES");
      log("P51_DOES_NOT_READ_OR_CHANGE_ORIGINAL_DSH_DATA=YES");
      log("P51_LONG_PRESS_TO_COPY_STATUS=YES");
    }
    if(!assertExactBridgeFailClosed()){
      fail("P47_NO_FALLBACK_BRIDGE_NOT_VERIFIED");
      return;
    }
    byte[] b=new byte[32];new SecureRandom().nextBytes(b);
    StringBuilder s=new StringBuilder(64);
    for(byte c:b)s.append(String.format(Locale.ROOT,"%02x",c&255));
    session=s.toString();
    log("P43_ORIGINAL_APK_ISOLATED_SERVICE_BIND_STARTED=YES");
    bound=bindService(new Intent(this,P43IsolatedWorker.class),
                      connection,Context.BIND_AUTO_CREATE);
    if(!bound)fail("BIND_FAILED");
    main.postDelayed(()->{if(!received&&!failed)fail("BINDER_ACK_TIMEOUT");},12000);
  }
  @Override protected void onDestroy(){
    if(p48!=null)p48.close();
    if(bound)unbindService(connection);
    super.onDestroy();
  }
}
