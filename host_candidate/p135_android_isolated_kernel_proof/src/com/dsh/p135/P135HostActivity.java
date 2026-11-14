package com.dsh.p135;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;

/** Test-only Android activity; no Node, file broker or external permission. */
public final class P135HostActivity extends Activity {
  private static final String TAG="DSH_P135_REAL_UID";
  private boolean bound;
  private boolean answered;
  private final Messenger replies=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg){
      if(answered||msg.what!=135)return;
      answered=true;
      Bundle value;
      try{value=msg.getData();}catch(RuntimeException fail){
        Log.e(TAG,"P135_BINDER_REPLY=INVALID");return;
      }
      boolean senderIsolated=Process.isIsolatedUid(msg.sendingUid)
          && msg.sendingUid!=Process.myUid();
      boolean identity=senderIsolated
          && msg.sendingUid==value.getInt("uid",-1)
          && value.getBoolean("isolated",false);
      boolean x86=value.getBoolean("x86Kernel",false);
      boolean guest=value.getBoolean("guestArm64Advertised",false);
      boolean denied=!value.getBoolean("realArm64GateAllowed",true);
      if(identity)Log.i(TAG,"P135_ACTUAL_ANDROID_ISOLATED_UID_DISTINCT=PASS");
      else Log.e(TAG,"P135_ACTUAL_ANDROID_ISOLATED_UID_DISTINCT=FAIL");
      if(x86 && guest)Log.i(TAG,"P135_X86_KERNEL_ADVERTISES_ARM64_GUEST=PASS");
      else Log.e(TAG,"P135_X86_KERNEL_ADVERTISES_ARM64_GUEST=FAIL");
      if(identity && x86 && guest && denied)
        Log.i(TAG,"P135_REAL_ANDROID_TRANSLATED_ARM64_DENIED_PREEXEC=PASS");
      else Log.e(TAG,"P135_REAL_ANDROID_TRANSLATED_ARM64_DENIED_PREEXEC=FAIL");
      Log.i(TAG,"P135_ORIGINAL_NODE_EXECUTED=NO");
      Log.i(TAG,"P135_ENGINE_MANAGER_EXECUTED=NO");
      Log.i(TAG,"P135_P109_NATIVE_AUTHORITY=DENY_ALL");
      Log.i(TAG,"P135_V139_RELEASE=BLOCKED");
    }
  });
  private final ServiceConnection connect=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      try{
        Message m=Message.obtain(null,135);
        m.replyTo=replies;
        new Messenger(binder).send(m);
      }catch(Exception fail){Log.e(TAG,"P135_MESSENGER_REQUEST=FAIL");}
    }
    @Override public void onServiceDisconnected(ComponentName name) {
      Log.e(TAG,"P135_WORKER_DISCONNECTED=FAIL");
    }
  };
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    TextView view=new TextView(this);
    view.setText("P135 ARM64 guest ABI rejection (disposable emulator only)");
    setContentView(view);
    bound=bindService(new Intent(this,P135IsolatedWorker.class),
        connect,Context.BIND_AUTO_CREATE);
    if(!bound)Log.e(TAG,"P135_BIND_SERVICE=FAIL");
  }
  @Override public void onDestroy(){
    if(bound)try{unbindService(connect);}catch(Exception ignored){}
    super.onDestroy();
  }
}
