package com.dsh.p20.boundary;

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
import android.system.Os;
import android.util.Log;
import android.widget.TextView;
import java.io.File;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Disposable Android35 proof. Host INTERNET permission, isolated child no
 * inherited permission. Only 127.0.0.1 and a disposable 0600 canary are used.
 * No Node binary, no actual personal secrets, no external connection.
 */
public final class P20BoundaryActivity extends Activity {
  private static final String TAG="DSH_P20_BOUNDARY";
  private File canary;
  private ServerSocket server;
  private boolean bound=false;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message m){
      if(m.what!=P20IsolatedWorker.PROBE)return;
      int kernelUid=m.sendingUid;
      boolean identity=kernelUid!=Process.myUid() && Process.isIsolatedUid(kernelUid);
      Bundle result;
      try { result=m.getData(); }
      catch(RuntimeException malformed){Log.e(TAG,"P20_INVALID_REPLY=FAIL");return;}
      boolean claimedUid=(result.getInt("uid",-1)==kernelUid);
      boolean isolated=result.getBoolean("isolated",false);
      boolean privateDenied=!result.getBoolean("canaryReadable",true)
          && canary!=null && canary.isFile() && canary.length()==3;
      boolean networkDenied=result.getBoolean("networkDeniedByOS",false);
      if(identity&&claimedUid&&isolated){
        Log.i(TAG,"P20_FRAMEWORK_ISOLATED_UID=PASS");
      }else{
        Log.e(TAG,"P20_FRAMEWORK_ISOLATED_UID=FAIL");
      }
      if(identity&&privateDenied)Log.i(TAG,"P20_HOST_PRIVATE_CANARY_UNREADABLE=PASS");
      else Log.e(TAG,"P20_HOST_PRIVATE_CANARY_UNREADABLE=FAIL");
      if(identity&&networkDenied&&server!=null&&!server.isClosed()){
        Log.i(TAG,"P20_HOST_INTERNET_CHILD_LOOPBACK_DENIED_BY_OS=PASS");
      }else{
        Log.e(TAG,"P20_HOST_INTERNET_CHILD_LOOPBACK_DENIED_BY_OS=FAIL");
      }
      Log.i(TAG,"P20_REAL_DSH_NODE_PROCESS_MIGRATED=NO");
      Log.i(TAG,"P20_ARM64_NODE_EXECUTION_ON_X86_64_EMULATOR=NOT_TESTED");
      ((TextView)findViewById(android.R.id.content)).setText("P20 boundary probe completed");
    }
  });
  private final ServiceConnection connection=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName component,IBinder binder){
      try {
        Message m=Message.obtain(null,P20IsolatedWorker.PROBE);
        m.replyTo=inbox;
        Bundle b=new Bundle();
        b.putString("canaryPath",canary.getAbsolutePath());
        b.putInt("port",server.getLocalPort());
        m.setData(b);
        new Messenger(binder).send(m);
      }catch(Exception err){Log.e(TAG,"P20_TEST_IPC_SEND=FAIL");}
    }
    @Override public void onServiceDisconnected(ComponentName component){
      Log.i(TAG,"P20_TEST_SERVICE_DISCONNECTED=YES");
    }
  };
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    TextView text=new TextView(this);
    text.setText("P20 permission boundary under test");
    setContentView(text);
    try {
      canary=new File(getFilesDir(),"p20-synthetic-host-canary.tmp");
      try(FileOutputStream output=new FileOutputStream(canary,false)){
        output.write(new byte[]{80,50,48});
        output.getFD().sync();
      }
      Os.chmod(canary.getAbsolutePath(),0600);
      if(canary.length()!=3)throw new IllegalStateException("canary missing");
      server=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));
      server.setSoTimeout(2000);
      try(Socket client=new Socket("127.0.0.1",server.getLocalPort());
          Socket accepted=server.accept()){
        if(!client.isConnected()||!accepted.isConnected())
          throw new IllegalStateException("host loopback unavailable");
      }
      Log.i(TAG,"P20_HOST_INTERNET_LOOPBACK_POSITIVE_CONTROL=PASS");
      bound=bindService(new Intent(this,P20IsolatedWorker.class),
          connection,Context.BIND_AUTO_CREATE);
      if(!bound)Log.e(TAG,"P20_BIND_ISOLATED=FAIL");
    }catch(Exception error){Log.e(TAG,"P20_SETUP=FAIL");}
  }
  @Override public void onDestroy(){
    if(bound)unbindService(connection);
    if(server!=null)try{server.close();}catch(Exception ignored){}
    if(canary!=null)canary.delete();
    super.onDestroy();
  }
}
