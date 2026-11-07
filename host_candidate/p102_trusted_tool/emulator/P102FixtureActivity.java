package com.dsh.p102.trustedtoolprobe;

import android.app.Activity;
import android.graphics.Rect;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

/**
 * Disposable Android35 emulator ONLY. No original DSH APK or signature.
 * Sole control is a native button; nothing approves automatically.
 */
public final class P102FixtureActivity extends Activity {
  private static final String TAG="P102_TOOL_BINDER";
  private final AtomicInteger trustedExecCount=new AtomicInteger();
  // Dedicated worker. The trusted button only schedules after disabling itself.
  // No executor body is ever run on Activity/UI or under the Binder port lock.
  private final ExecutorService approvalWorker=Executors.newSingleThreadExecutor(task->{
    Thread thread=new Thread(task,"P102-native-approval-worker");
    thread.setDaemon(true);
    return thread;
  });
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
        if(approveButton!=null)approveButton.post(this::reportNativeApprovalView);
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
    // P169: only disposable Android35/36 zero-permission synthetic lab.
    // Android36 may resume a newly-launched Activity without granting its
    // actual window focus if display sleep races with startup. Ask Android
    // to wake the Activity and retain the screen for this short lab test.
    // This does NOT grant focus or trust: P161 still requires the genuine
    // onWindowFocusChanged(YES) and same pending native Binder generation.
    setTurnScreenOn(true);
    getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    approveButton=new Button(this);
    approveButton.setAllCaps(false);
    approveButton.setText("P102 standalone lab\nWaiting for isolated Binder request\nNo access to original DSH");
    approveButton.setEnabled(false);
    approveButton.setContentDescription("P102_TRUSTED_NATIVE_APPROVAL");
    setContentView(approveButton);
    approveButton.setOnClickListener(v->{
      final String approvedId=pendingCallId;
      approveButton.setEnabled(false);
      approveButton.setText("Native approval accepted\nChecking trusted worker");
      try{
        approvalWorker.execute(()->{
          final boolean dispatched=port.onTrustedNativeUiApprove(approvedId);
          Log.i(TAG,"P102_NATIVE_UI_APPROVAL_DISPATCH="+(dispatched?"YES":"NO"));
          runOnUiThread(()->{
            if(isFinishing()||isDestroyed())return;
            approveButton.setText(dispatched
              ? "Native approval dispatched\nInspect P102_TOOL_BINDER logs for terminal/replay"
              : "Native approval rejected\nNo tool was approved");
          });
        });
      }catch(RejectedExecutionException stopped){
        Log.e(TAG,"P102_NATIVE_APPROVAL_WORKER_NOT_AVAILABLE");
        port.onTrustedUiBackground();
        approveButton.setText("Native approval rejected\nWorker unavailable");
      }
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
  // Standalone synthetic lab only: report actual *visible native button*
  // geometry after the framework grants window focus and a pending call.
  // Never log the session ID, user app state, or any private content.
  private void reportNativeApprovalView(){
    if(approveButton==null || pendingCallId==null || !hasWindowFocus() ||
       !approveButton.isShown() || !approveButton.isEnabled() ||
       isFinishing() || isDestroyed())return;
    Rect r=new Rect();
    if(approveButton.getGlobalVisibleRect(r) &&
       r.width()>=8 && r.height()>=8 &&
       r.left>=0 && r.top>=0 && r.right<=10000 && r.bottom<=10000)
      Log.i(TAG,"P162_VISIBLE_NATIVE_APPROVAL_RECT="+
          r.left+","+r.top+","+r.right+","+r.bottom);
  }
  @Override public void onWindowFocusChanged(boolean hasFocus){
    super.onWindowFocusChanged(hasFocus);
    Log.i(TAG,"P102_NATIVE_WINDOW_FOCUS="+(hasFocus?"YES":"NO"));
    if(hasFocus && approveButton!=null)approveButton.post(this::reportNativeApprovalView);
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
    approvalWorker.shutdown();
    super.onDestroy();
  }
}
