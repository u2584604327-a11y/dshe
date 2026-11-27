package com.dsh.p301probe;

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

/** One-use, no-network, QEMU-only host; never original DSH EngineManager. */
public final class ProbeActivity extends Activity {
  private static final String TAG="P301_HOST";
  private static final byte[] PAYLOAD="P301_SYNTHETIC".getBytes(StandardCharsets.US_ASCII);
  private Messenger remote;
  // A/B only: keep the host-side local read endpoint alive until the
  // isolated worker has finished its own reliable-pipe EOF verification.
  private ParcelFileDescriptor heldLocalReader;
  private boolean bound=false;
  private int phase=0;
  private boolean terminated=false;
  private void releaseHeldReader() {
    final ParcelFileDescriptor fd=heldLocalReader;
    heldLocalReader=null;
    if(fd!=null) {
      try {
        fd.close();
        Log.i(TAG,"P301_HOST_READER_RELEASED_AFTER_WORKER=PASS");
      } catch(Exception fail) {
        // A release failure cannot authorize a successful test.
        Log.i(TAG,"P301_DENY_HOST_READER_RELEASE=DENY");
      }
    }
  }
  private void deny(String cause){
    if(terminated)return;
    terminated=true;
    Log.i(TAG,"P301_DENY_"+cause+"=DENY");
    releaseHeldReader();
    finish();
  }
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg) {
      if(terminated)return;
      if(msg.what!=IsolatedPipeService.REPLY ||
          !Process.isIsolatedUid(msg.sendingUid)) {
        deny("REPLY_IDENTITY");return;
      }
      String outcome=null;
      try {
        Bundle data=msg.getData();
        if(data!=null)outcome=data.getString("result");
      } catch(RuntimeException fail) {deny("REPLY_PARCEL");return;}
      if(phase==0 && "DENY_MISSING_FD".equals(outcome)) {
        Log.i(TAG,"P301_MISSING_FD_REJECTED=PASS");
        phase=1;
        sendFd();
      } else if(phase==1 && "FD_PAYLOAD_OK".equals(outcome)) {
        Log.i(TAG,"P301_HOST_FD_RECEIPT=PASS");
        phase=2;
        terminated=true;
        releaseHeldReader();
        finish();
      } else if(phase==1 && IsolatedPipeService.FAILURES.contains(outcome)) {
        deny("WORKER_FAILURE");
      } else {
        deny("UNEXPECTED_REPLY");
      }
    }
  });
  private final ServiceConnection conn=new ServiceConnection() {
    @Override public void onServiceConnected(ComponentName component, IBinder binder) {
      if(terminated)return;
      remote=new Messenger(binder);
      Message m=Message.obtain(null,IsolatedPipeService.REQUEST);
      m.replyTo=inbox;
      try {remote.send(m);}
      catch(RemoteException e){deny("INITIAL_SEND");}
    }
    @Override public void onServiceDisconnected(ComponentName component){
      if(!terminated)deny("DISCONNECTED");
    }
  };
  private void sendFd() {
    ParcelFileDescriptor[] pipe=null;
    try {
      pipe=ParcelFileDescriptor.createReliablePipe();
      Message m=Message.obtain(null,IsolatedPipeService.REQUEST);
      m.replyTo=inbox;
      Bundle data=new Bundle();
      data.putParcelable("fd",pipe[0]);
      m.setData(data);
      remote.send(m);
      Log.i(TAG,"P301_HOST_FD_SENT=PASS");
      // Controlled AB-2: preserve the host's local read-side status channel
      // until after the worker has returned the terminal Binder reply.
      // AB-1 kept it only until writer close; that still produced DEAD.
      // This is an isolated synthetic experiment, NOT a production protocol.
      heldLocalReader=pipe[0];
      pipe[0]=null;
      Log.i(TAG,"P301_HOST_READER_RETAINED=PASS");
      try(ParcelFileDescriptor.AutoCloseOutputStream out =
          new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
        out.write(PAYLOAD);
        out.flush();
      }
      pipe[1]=null;
      Log.i(TAG,"P301_HOST_WRITE_COMPLETE=PASS");
    } catch(Exception ex) { deny("HOST_PIPE_IO"); }
    finally {
      if(pipe!=null)for(ParcelFileDescriptor fd:pipe)if(fd!=null){
        try {fd.close();}catch(Exception ignore){}
      }
    }
  }
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    if(state!=null){deny("RESTORED_STATE");return;}
    bound=bindService(new Intent(this,IsolatedPipeService.class),conn,Context.BIND_AUTO_CREATE);
    if(!bound)deny("BIND_SERVICE");
  }
  @Override public void onDestroy(){
    // Process/activity recreation and cancellation must not leak a host FD.
    releaseHeldReader();
    if(bound){unbindService(conn);bound=false;}
    super.onDestroy();
  }
}
