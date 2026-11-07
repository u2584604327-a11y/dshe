package com.dsh.p193probe;

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
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;
import java.nio.charset.StandardCharsets;

/** Host FD creation + real framework Binder caller UID validation. */
public final class ProbeActivity extends Activity {
  private static final String TAG="P193_HOST";
  private Messenger remote;
  private boolean bound=false;
  private int phase=0;
  private void deny(){Log.i(TAG,"P193_DENY_HOST=DENY");finish();}
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg){
      if(msg.what!=IsolatedPipeService.REPLY ||
         !Process.isIsolatedUid(msg.sendingUid)){
        Log.i(TAG,"P193_DENY_REPLY_IDENTITY=DENY");deny();return;
      }
      String outcome;
      try{outcome=msg.getData().getString("result");}
      catch(RuntimeException bad){
        Log.i(TAG,"P193_DENY_REPLY_PARCEL=DENY");deny();return;
      }
      if(phase==0 && "DENY_MISSING_FD".equals(outcome)){
        Log.i(TAG,"P193_MISSING_FD_REJECTED=PASS");
        phase=1;sendFd();
      }else if(phase==1 && "FD_PAYLOAD_OK".equals(outcome)){
        phase=2;Log.i(TAG,"P193_ANDROID35_HOST_ISOLATED_BINDER_FD=PASS");finish();
      }else {
        if(phase==1 && "DENY_BAD_FRAME".equals(outcome))
          Log.i(TAG,"P193_DENY_RETURN_FRAME=DENY");
        else if(phase==1 && "DENY_FD_READ".equals(outcome))
          Log.i(TAG,"P193_DENY_RETURN_READ=DENY");
        else Log.i(TAG,"P193_DENY_REPLY_PHASE=DENY");
        deny();
      }
    }
  });
  private final ServiceConnection conn=new ServiceConnection(){
    @Override public void onServiceConnected(ComponentName c,IBinder b){
      remote=new Messenger(b);
      Message msg=Message.obtain(null,IsolatedPipeService.REQUEST);
      msg.replyTo=inbox;
      try{remote.send(msg);}catch(RemoteException e){
        Log.i(TAG,"P193_DENY_INITIAL_SEND=DENY");deny();
      }
    }
    @Override public void onServiceDisconnected(ComponentName c){if(phase!=2){
      Log.i(TAG,"P193_DENY_SERVICE_DISCONNECTED=DENY");deny();
    }}
  };
  private void sendFd(){
    ParcelFileDescriptor[] pair=null;
    try{
      pair=ParcelFileDescriptor.createReliablePipe();
      Message msg=Message.obtain(null,IsolatedPipeService.REQUEST);
      msg.replyTo=inbox;
      Bundle b=new Bundle();b.putParcelable("fd",pair[0]);msg.setData(b);
      remote.send(msg);
      pair[0].close();pair[0]=null;
      try(ParcelFileDescriptor.AutoCloseOutputStream out=
          new ParcelFileDescriptor.AutoCloseOutputStream(pair[1])){
        out.write("P193_SYNTHETIC".getBytes(StandardCharsets.US_ASCII));
        out.flush();
      }
      pair[1]=null;
    }catch(Exception e){
      Log.i(TAG,"P193_DENY_FD_SEND=DENY");deny();
    }
    finally{if(pair!=null)for(ParcelFileDescriptor fd:pair)if(fd!=null){
      try{fd.close();}catch(Exception ignored){}
    }}
  }
  @Override public void onCreate(Bundle old){
    super.onCreate(old);
    if(old!=null){deny();return;}
    bound=bindService(new Intent(this,IsolatedPipeService.class),conn,Context.BIND_AUTO_CREATE);
    if(!bound){
      Log.i(TAG,"P193_DENY_BIND_SERVICE=DENY");deny();
    }
  }
  @Override public void onDestroy(){
    if(bound){unbindService(conn);bound=false;}
    super.onDestroy();
  }
}
