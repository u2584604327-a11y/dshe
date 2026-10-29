package com.dsh.android.p43;
import android.app.Activity;
import android.content.*;
import android.os.*;
import android.widget.TextView;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * P43 temporary exported test entry exists ONLY in the throwaway emulator APK.
 * It MUST NOT be present in any user-release build.
 */
public final class P43ProbeActivity extends Activity {
  private final Handler main=new Handler(Looper.getMainLooper());
  private final StringBuilder status=new StringBuilder();
  private String session;
  private final P44VirtualDeviceProfile simulatedProfile=P44VirtualDeviceProfile.syntheticDemo();
  private TextView label;
  private boolean bound,received,failed;
  private Messenger remote;
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
      received=true;
      log("P44_ORIGINAL_DSH_PROFILE_TO_ISOLATED_WORKER=PASS");
      log("P44_HOST_SELECTED_VIRTUAL_PROFILE_HASH_VALIDATED=PASS");
      log("P44_ACTUAL_SYSTEM_VM=NO");
      log("P44_REAL_DEVICE_IDENTITY_MODIFIED=NO");
      log("P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS");
      log("P43_ORIGINAL_DSH_APPLICATION_AND_ISOLATED_SERVICE_BOUND=PASS");
      log("P43_REAL_NODE_IN_ORIGINAL_ENGINE=NO");
      log("P43_V139_RELEASE=BLOCKED");
    }
  });
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      remote=new Messenger(binder);
      Message m=Message.obtain(null,P43IsolatedWorker.INIT);
      Bundle b=new Bundle();b.putString("session",session);
      b.putString("p44_profile",simulatedProfile.wire());
      m.replyTo=replies;m.setData(b);
      try{remote.send(m);}catch(RemoteException e){fail("BINDER_SEND_FAILED");}
    }
    @Override public void onServiceDisconnected(ComponentName n){fail("SERVICE_DISCONNECTED");}
    @Override public void onBindingDied(ComponentName n){fail("BINDING_DIED");}
    @Override public void onNullBinding(ComponentName n){fail("NULL_BINDING");}
  };
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    label=new TextView(this);label.setTextSize(16);setContentView(label);
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
    if(bound)unbindService(connection);
    super.onDestroy();
  }
}
