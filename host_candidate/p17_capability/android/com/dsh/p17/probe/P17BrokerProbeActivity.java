package com.dsh.p17.probe;
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
import android.os.SystemClock;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.dsh.p17.P17CapabilityGate;
/** Test-only Android shell: a real UI click grants exactly one count.
 * Uses Messenger's framework-attested Message.sendingUid; never trusts a
 * client-supplied uid field. Never exposes files, URLs, shell or network.
 */
public final class P17BrokerProbeActivity extends Activity {
  private static final String TAG="DSH_P17_BROKER";
  private final P17CapabilityGate gate=new P17CapabilityGate(SystemClock::elapsedRealtime);
  private final Messenger broker=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message m) {
      if(m.what==IsolatedCountWorker.HELLO) {
        workerUid=m.sendingUid;
        if(workerUid==Process.myUid()||!Process.isIsolatedUid(workerUid)||
           !m.getData().getBoolean("isolated",false)) {
          Log.e(TAG,"P17_REAL_BINDER_UID=FAIL");return;
        }
        Log.i(TAG,"P17_REAL_BINDER_UID=PASS");
        send(IsolatedCountWorker.TEST_UNGRANTED,null);
      }else if(m.what==IsolatedCountWorker.QUERY) {
        if(m.sendingUid!=workerUid||!Process.isIsolatedUid(m.sendingUid)) {
          Log.e(TAG,"P17_UNAUTHENTICATED_UID=DENIED");return;
        }
        String scope=m.getData().getString("scope","");
        String token=m.getData().getString("token","");
        boolean approved=gate.consume(token,scope,m.sendingUid);
        attempts++;
        if(attempts==1) {
          if(!approved){Log.i(TAG,"P17_PREGRANT_DENIED=PASS");button.setEnabled(true);}
          else Log.e(TAG,"P17_PREGRANT_DENIED=FAIL");
        }else if(attempts==2) {
          if(approved)Log.i(TAG,"P17_ONE_SHOT_APPROVED=PASS");
          else Log.e(TAG,"P17_ONE_SHOT_APPROVED=FAIL");
        }else if(attempts==3) {
          if(!approved)Log.i(TAG,"P17_REPLAY_DENIED=PASS");
          else Log.e(TAG,"P17_REPLAY_DENIED=FAIL");
        }else if(attempts==4) {
          if(!approved && "READ_PRIVATE_FILES".equals(scope))
            Log.i(TAG,"P17_ARBITRARY_FILE_SCOPE_DENIED=PASS");
          else Log.e(TAG,"P17_ARBITRARY_FILE_SCOPE_DENIED=FAIL");
          Log.i(TAG,"P17_DSH_NODE_MIGRATED=NO");
        }
      }
    }
  });
  private int workerUid=-1,attempts=0;
  private Messenger remote;
  private Button button;
  private boolean bound=false;
  private final ServiceConnection connection=new ServiceConnection() {
    @Override public void onServiceConnected(ComponentName n,IBinder b) {
      remote=new Messenger(b);
      send(IsolatedCountWorker.HELLO,null);
    }
    @Override public void onServiceDisconnected(ComponentName n){
      remote=null;gate.revokeAll();button.setEnabled(false);
    }
  };
  private void send(int code,String grant) {
    if(remote==null)return;
    try {
      Message m=Message.obtain(null,code);
      m.replyTo=broker;
      if(grant!=null){Bundle b=new Bundle();b.putString("token",grant);m.setData(b);}
      remote.send(m);
    }catch(Exception error){Log.e(TAG,"P17_IPC_SEND=FAIL");}
  }
  @Override public void onCreate(Bundle b) {
    super.onCreate(b);
    LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
    TextView heading=new TextView(this);heading.setText("一次性计数授权（安全隔离测试）");
    root.addView(heading,new LinearLayout.LayoutParams(-1,90));
    button=new Button(this);button.setText("批准一次计数");button.setEnabled(false);
    root.addView(button,new LinearLayout.LayoutParams(-1,140));
    setContentView(root);
    button.setOnClickListener(v->{
      if(workerUid<0||!Process.isIsolatedUid(workerUid)||attempts!=1) {
        Log.e(TAG,"P17_GESTURE_PRECONDITION=DENIED");return;
      }
      button.setEnabled(false);
      String token=gate.approveOnce(P17CapabilityGate.SCOPE_METADATA_COUNT,
                                   workerUid,20000);
      Log.i(TAG,"P17_TRUSTED_UI_GRANT=PASS");
      send(IsolatedCountWorker.GRANT,token);
    });
    bound=bindService(new Intent(this,IsolatedCountWorker.class),connection,Context.BIND_AUTO_CREATE);
    if(!bound)Log.e(TAG,"P17_BIND_FAILED");
  }
  @Override public void onDestroy(){
    gate.revokeAll();
    if(bound)unbindService(connection);
    super.onDestroy();
  }
}
