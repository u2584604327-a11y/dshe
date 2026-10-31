package com.dsh.p102.trustedtoolprobe;

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
import com.dsh.android.p102.P102AndroidToolBinderPort;
import com.dsh.android.p102.P102TrustedToolGate;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Disposable Android35 emulator ONLY. No original DSH APK or signature.
 * Sole control is a native button; nothing approves automatically.
 */
public final class P102FixtureActivity extends Activity {
  private static final String TAG="P102_TOOL_BINDER";
  private final AtomicInteger trustedExecCount=new AtomicInteger();
  private String pendingCallId;
  private Button approveButton;
  private final P102AndroidToolBinderPort port=new P102AndroidToolBinderPort(
      (callId,toolName)->{
        pendingCallId=callId;
        if(approveButton!=null){
          approveButton.setEnabled(true);
          approveButton.setText("P102 isolated Binder lab\nApprove ONE synthetic read (no DSH access)");
        }
        Log.i(TAG,"P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS");
      },
      (name,args)->{
        if(!P102TrustedToolGate.TOOL.equals(name)||
           !P102TrustedToolGate.FIXED_ARGS.equals(args)){
          Log.e(TAG,"P102_EXECUTOR_UNEXPECTED_ARGUMENTS=FAIL");return false;
        }
        int n=trustedExecCount.incrementAndGet();
        Log.i(TAG,"P102_TRUSTED_EXECUTION_COUNT="+n);
        return n==1;
      },
      // Emulator fixture only. Production MUST validate against the
      // exact original live SessionStore/ToolRuntime, never this literal.
      (originalSessionId,originalCallId)->
        "p99_session_controller_once".equals(originalSessionId)&&
        "call_p102_e2e".equals(originalCallId));
  private Messenger isolated;
  private boolean bound;
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      isolated=new Messenger(binder);
      try{
        Message init=Message.obtain(null,P102IsolatedWorker.INIT);
        init.replyTo=port.trustedInbox();
        isolated.send(init);
      }catch(Exception e){Log.e(TAG,"P102_REAL_BINDER_HANDSHAKE=FAIL");}
    }
    @Override public void onServiceDisconnected(ComponentName name){
      isolated=null;port.onWorkerDisconnected();
    }
    @Override public void onBindingDied(ComponentName name){
      isolated=null;port.onBinderDeath();
    }
    @Override public void onNullBinding(ComponentName name){
      isolated=null;port.onWorkerDisconnected();
    }
  };
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    approveButton=new Button(this);
    approveButton.setAllCaps(false);
    approveButton.setText("P102 standalone lab\nWaiting for isolated Binder request\nNo access to original DSH");
    approveButton.setEnabled(false);
    approveButton.setContentDescription("P102_TRUSTED_NATIVE_APPROVAL");
    setContentView(approveButton);
    approveButton.setOnClickListener(v->{
      boolean dispatched=port.onTrustedNativeUiApprove(pendingCallId);
      Log.i(TAG,"P102_NATIVE_UI_APPROVAL_DISPATCH="+(dispatched?"YES":"NO"));
      approveButton.setEnabled(false);
      approveButton.setText(dispatched
        ? "Native approval dispatched\nInspect P102_TOOL_BINDER logs for terminal/replay"
        : "Native approval rejected\nNo tool was approved");
    });
  }
  @Override protected void onResume(){
    super.onResume();
    if(bound)return;
    // Bind only while the native UI is actively visible and ready for consent.
    // A prior onStop revokes forever; a new resume needs a fresh Binder session.
    pendingCallId=null;
    approveButton.setEnabled(false);
    approveButton.setText("P102 standalone lab\nWaiting for isolated Binder request\nNo access to original DSH");
    port.onTrustedServiceBindingInitiated();
    bound=bindService(new Intent(this,P102IsolatedWorker.class),
      connection,Context.BIND_AUTO_CREATE);
    if(!bound)Log.e(TAG,"P102_REAL_SERVICE_BIND=FAIL");
    else Log.i(TAG,"P102_NATIVE_FOREGROUND_BIND=PASS");
  }
  @Override protected void onStop(){
    // Never retain an approved or pending slot while the Activity is hidden.
    port.onTrustedUiBackground();
    if(bound){
      unbindService(connection);
      bound=false;
      isolated=null;
    }
    pendingCallId=null;
    approveButton.setEnabled(false);
    Log.i(TAG,"P102_NATIVE_BACKGROUND_REVOKE=PASS");
    super.onStop();
  }
  @Override public void onDestroy(){
    port.onWorkerDisconnected();
    if(bound)unbindService(connection);
    bound=false;isolated=null;
    super.onDestroy();
  }
}
