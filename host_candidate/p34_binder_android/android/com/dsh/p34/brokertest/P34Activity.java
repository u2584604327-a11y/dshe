package com.dsh.p34.brokertest;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.dsh.p32.P32AndroidBinderPort;

/** Android emulator real OS Binder transport test. No actual original Node. */
public final class P34Activity extends Activity {
  private static final String TAG="P34_BINDER_LAB";
  private final P32AndroidBinderPort trusted=new P32AndroidBinderPort();
  private Messenger isolated;
  private boolean bound=false;
  private Button approve;
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      isolated=new Messenger(binder);
      try{
        Message init=Message.obtain(null,P34IsolatedWorker.INIT);
        init.replyTo=trusted.getTrustedHostInbox();
        isolated.send(init);
      }catch(Exception e){Log.e(TAG,"P34_REAL_IPC_HANDSHAKE=FAIL");}
    }
    @Override public void onServiceDisconnected(ComponentName name){
      isolated=null;
      trusted.onWorkerDisconnect();
    }
    @Override public void onBindingDied(ComponentName name){
      isolated=null;
      trusted.onBinderDeath();
    }
    @Override public void onNullBinding(ComponentName name){
      isolated=null;
      trusted.onWorkerDisconnect();
    }
  };
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    LinearLayout root=new LinearLayout(this);
    root.setOrientation(LinearLayout.VERTICAL);
    approve=new Button(this);
    approve.setText("批准一次合成计数（可信原生 UI）");
    approve.setContentDescription("P34_NATIVE_APPROVE_ONCE");
    root.addView(approve,new LinearLayout.LayoutParams(-1,190));
    TextView info=new TextView(this);
    info.setText("独立 Android 35 Binder 沙箱实验。只测试合成 METADATA_COUNT，"
      +"没有 Node、网络、文件或真实 DSH 操作。");
    root.addView(info);
    setContentView(root);
    approve.setOnClickListener(v->{
      boolean sent=trusted.onTrustedUiApproveOnceClick();
      Log.i(TAG,"P34_NATIVE_UI_CLICK_GRANT_SENT="+(sent?"YES":"NO"));
      approve.setEnabled(false);  // cannot silently approve again
    });
    trusted.onTrustedServiceBindingInitiated();
    bound=bindService(new Intent(this,P34IsolatedWorker.class),
      connection,Context.BIND_AUTO_CREATE);
    if(!bound)Log.e(TAG,"P34_REAL_SERVICE_BIND=FAIL");
  }
  @Override protected void onStop(){
    trusted.onTrustedUiBackground();
    super.onStop();
  }
  @Override public void onDestroy(){
    trusted.onWorkerDisconnect();
    if(bound)unbindService(connection);
    bound=false;isolated=null;
    super.onDestroy();
  }
}
