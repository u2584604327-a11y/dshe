package com.dsh.p102.trustedtoolprobe;

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
import com.dsh.android.p102.P102AndroidToolBinderPort;
import com.dsh.android.p102.P102TrustedToolGate;

/** Isolated, nonexported, zero-permission worker: fixed synthetic tool only. */
public final class P102IsolatedWorker extends Service {
  public static final int INIT=10299;
  private static final String TAG="P102_TOOL_BINDER";
  private static final String CALL="call_p102_e2e";
  private Messenger host;
  private int hostUid=-1;
  private String session;
  private int stage;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg){
      try{
        if(msg.what==INIT){
          if(host!=null||!Process.isIsolated()||msg.replyTo==null||
             Process.isIsolatedUid(msg.sendingUid)||
             msg.sendingUid!=getApplicationInfo().uid){
            Log.e(TAG,"P102_AUTHENTICATED_INIT=FAIL");return;
          }
          hostUid=msg.sendingUid;host=msg.replyTo;
          Log.i(TAG,"P102_WORKER_INIT_FROM_TRUSTED_HOST=PASS");
          Message hello=Message.obtain(null,P102AndroidToolBinderPort.HELLO);
          hello.replyTo=inbox;host.send(hello);
          return;
        }
        if(host==null){
          Log.e(TAG,"P102_WORKER_HOST_NOT_BOUND=FAIL");return;
        }
        if(msg.sendingUid!=hostUid){
          // Observe UID mismatch, never weaken the authority check.
          Log.e(TAG,"P102_WORKER_HOST_UID_MISMATCH=FAIL");return;
        }
        if(msg.what==P102AndroidToolBinderPort.HELLO_REPLY){
          Log.i(TAG,"P102_WORKER_HELLO_REPLY_RECEIVED=PASS");
          if(stage!=0)return;
          Bundle b=msg.getData();session=b.getString("session");
          if(session==null||!session.matches("[a-f0-9]{64}")||
             !"BOUND_NOT_APPROVED".equals(b.getString("status"))){
            Log.e(TAG,"P102_HOST_MINTED_SESSION=FAIL");return;
          }
          stage=1;
          sendRequest();
        }else if(msg.what==P102AndroidToolBinderPort.REQUEST_ACK){
          Log.i(TAG,"P102_WORKER_REQUEST_ACK_RECEIVED=YES");
          String status=msg.getData().getString("status","");
          if(stage==1){
            if(!"PENDING_NATIVE_APPROVAL".equals(status)){
              Log.e(TAG,"P102_PREAPPROVAL_REQUEST_GATE=FAIL");return;
            }
            stage=2;
            Log.i(TAG,"P102_PREAPPROVAL_REQUEST_GATE=PASS");
            Log.i(TAG,"P102_REAL_ISOLATED_UID="+Process.myUid());
          }else if(stage==3){
            if(!"REJECTED".equals(status)){
              Log.e(TAG,"P102_REPLAY_REQUEST_DENIED=FAIL");return;
            }
            stage=4;
            Log.i(TAG,"P102_REPLAY_REQUEST_DENIED=PASS");
            Log.i(TAG,"P102_REAL_BINDER_NATIVE_TOOL_E2E=PASS");
            Log.i(TAG,"P102_ORIGINAL_DSH_NODE_CONNECTED=NO");
          }
        }else if(msg.what==P102AndroidToolBinderPort.TOOL_TERMINAL){
          Log.i(TAG,"P102_WORKER_TERMINAL_FRAME_RECEIVED=YES");
          if(stage!=2){
            Log.e(TAG,"P102_TERMINAL_UNEXPECTED_STAGE=FAIL");return;
          }
          Bundle b=msg.getData();
          if(!CALL.equals(b.getString("callId"))||
             !"SUCCESS".equals(b.getString("status"))||
             !"fixture-read-success".equals(b.getString("fixedResult"))||
             b.getBoolean("outcomeUnknown",true)||
             b.getBoolean("retrySafe",true)){
            Log.e(TAG,"P102_TERMINAL_TOOL_RESULT=FAIL");return;
          }
          stage=3;
          Log.i(TAG,"P102_TERMINAL_TOOL_RESULT=PASS");
          sendRequest(); // same call replay MUST be refused.
        }
      }catch(Exception invalid){
        Log.e(TAG,"P102_BINDER_PROTOCOL=FAIL_"+invalid.getClass().getSimpleName());
      }
    }
    private void sendRequest()throws Exception{
      Message request=Message.obtain(null,P102AndroidToolBinderPort.REQUEST);
      request.replyTo=inbox;
      Bundle data=new Bundle();
      data.putString("session",session);
      data.putString("originalSessionId","p99_session_controller_once");
      data.putString("callId",CALL);
      data.putString("toolName",P102TrustedToolGate.TOOL);
      data.putString("arguments",P102TrustedToolGate.FIXED_ARGS);
      request.setData(data);
      host.send(request);
    }
  });
  @Override public IBinder onBind(Intent intent){
    if(!Process.isIsolated())throw new SecurityException("isolated UID required");
    return inbox.getBinder();
  }
  @Override public void onDestroy(){
    stage=0;host=null;session=null;hostUid=-1;
    super.onDestroy();
  }
}
