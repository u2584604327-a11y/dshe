package com.dsh.p302probe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Configuration;
import android.content.pm.ActivityInfo;
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
  private static final String TAG="P302_HOST";
  private static final byte[] PAYLOAD=createPayload();
  private static byte[] createPayload() {
    byte[] data=new byte[65536];
    for(int i=0;i<data.length;i++)data[i]=(byte)((i*31+7)&255);
    return data;
  }
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
        Log.i(TAG,"P302_HOST_READER_RELEASED_AFTER_WORKER=PASS");
      } catch(Exception fail) {
        // A release failure cannot authorize a successful test.
        Log.i(TAG,"P302_DENY_HOST_READER_RELEASE=DENY");
      }
    }
  }
  private void deny(String cause){
    if(terminated)return;
    terminated=true;
    Log.i(TAG,"P302_DENY_"+cause+"=DENY");
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
        Log.i(TAG,"P302_MISSING_FD_REJECTED=PASS");
        phase=1;
        sendFd();
      } else if(phase==1 && "FD_PAYLOAD_OK".equals(outcome)) {
        Log.i(TAG,"P302_HOST_FD_RECEIPT=PASS");
        phase=2;
        Message replay=Message.obtain(null,IsolatedPipeService.REQUEST);
        replay.replyTo=inbox;
        try {remote.send(replay); Log.i(TAG,"P302_HOST_REPLAY_SENT=PASS");}
        catch(RemoteException fail) {deny("REPLAY_SEND");}
      } else if(phase==2 && "DENY_WORKER_REPLAY".equals(outcome)) {
        Log.i(TAG,"P302_HOST_REPLAY_DENIED=PASS");
        phase=3;
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
      Log.i(TAG,"P302_LIFECYCLE_SERVICE_CONNECTED=OBSERVED");
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
      Log.i(TAG,"P302_HOST_FD_SENT=PASS");
      // Controlled AB-2: preserve the host's local read-side status channel
      // until after the worker has returned the terminal Binder reply.
      // AB-1 kept it only until writer close; that still produced DEAD.
      // This is an isolated synthetic experiment, NOT a production protocol.
      heldLocalReader=pipe[0];
      pipe[0]=null;
      Log.i(TAG,"P302_HOST_READER_RETAINED=PASS");
      Log.i(TAG,"P302_LIFECYCLE_STREAM_WRITE_BEGIN=OBSERVED");
      try(ParcelFileDescriptor.AutoCloseOutputStream out =
          new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
        out.write(PAYLOAD);
        out.flush();
      }
      pipe[1]=null;
      Log.i(TAG,"P302_LIFECYCLE_STREAM_WRITE_END=OBSERVED");
      Log.i(TAG,"P302_HOST_WRITE_COMPLETE=PASS");
    } catch(Exception ex) { deny("HOST_PIPE_IO"); }
    finally {
      if(pipe!=null)for(ParcelFileDescriptor fd:pipe)if(fd!=null){
        try {fd.close();}catch(Exception ignore){}
      }
    }
  }
  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    Log.i(TAG,state==null ? "P302_LIFECYCLE_CREATE_FRESH=OBSERVED" : "P302_LIFECYCLE_CREATE_RESTORED=OBSERVED");
    if(state!=null){deny("RESTORED_STATE");return;}
    bound=bindService(new Intent(this,IsolatedPipeService.class),conn,Context.BIND_AUTO_CREATE);
    if(!bound)deny("BIND_SERVICE");
  }
  @Override public void onConfigurationChanged(Configuration newConfig){
    super.onConfigurationChanged(newConfig);
    Log.i(TAG,"P302_LIFECYCLE_CONFIG_HANDLED=OBSERVED");
  }
  @Override protected void onSaveInstanceState(Bundle outState){
    Log.i(TAG,"P302_LIFECYCLE_SAVE_STATE=OBSERVED");
    super.onSaveInstanceState(outState);
  }
  @Override protected void onStop(){
    Log.i(TAG,"P302_LIFECYCLE_STOP=OBSERVED");
    super.onStop();
  }
  // P305 diagnostic only: identify *categories* of configuration changes.
  // No raw Configuration, mask, process identifiers or locale values are logged.
  private void logConfigChangeClasses() {
    final int mask=getChangingConfigurations();
    final int[] bits=new int[]{
      ActivityInfo.CONFIG_FONT_SCALE,
      ActivityInfo.CONFIG_MCC,
      ActivityInfo.CONFIG_MNC,
      ActivityInfo.CONFIG_LOCALE,
      ActivityInfo.CONFIG_TOUCHSCREEN,
      ActivityInfo.CONFIG_KEYBOARD,
      ActivityInfo.CONFIG_KEYBOARD_HIDDEN,
      ActivityInfo.CONFIG_NAVIGATION,
      ActivityInfo.CONFIG_ORIENTATION,
      ActivityInfo.CONFIG_SCREEN_LAYOUT,
      ActivityInfo.CONFIG_UI_MODE,
      ActivityInfo.CONFIG_SCREEN_SIZE,
      ActivityInfo.CONFIG_SMALLEST_SCREEN_SIZE,
      ActivityInfo.CONFIG_DENSITY,
      ActivityInfo.CONFIG_LAYOUT_DIRECTION,
      ActivityInfo.CONFIG_COLOR_MODE,
      ActivityInfo.CONFIG_GRAMMATICAL_GENDER,
      ActivityInfo.CONFIG_ASSETS_PATHS
    };
    final String[] names=new String[]{
      "FONT_SCALE",
      "MCC",
      "MNC",
      "LOCALE",
      "TOUCHSCREEN",
      "KEYBOARD",
      "KEYBOARD_HIDDEN",
      "NAVIGATION",
      "ORIENTATION",
      "SCREEN_LAYOUT",
      "UI_MODE",
      "SCREEN_SIZE",
      "SMALLEST_SCREEN_SIZE",
      "DENSITY",
      "LAYOUT_DIRECTION",
      "COLOR_MODE",
      "GRAMMATICAL_GENDER",
      "ASSETS_PATHS"
    };
    int seen=0;
    for(int i=0;i<bits.length;i++) {
      if((mask & bits[i])!=0) {
        Log.i(TAG,"P305_CONFIG_CHANGE_"+names[i]+"=OBSERVED");
        seen |= bits[i];
      }
    }
    if(mask==0)Log.i(TAG,"P305_CONFIG_CHANGE_ZERO=OBSERVED");
    if((mask & ~seen)!=0)Log.i(TAG,"P305_CONFIG_CHANGE_OTHER=OBSERVED");
  }
  @Override public void onDestroy(){
    if(isChangingConfigurations())logConfigChangeClasses();
    Log.i(TAG,isChangingConfigurations() ? "P302_LIFECYCLE_DESTROY_CONFIG=OBSERVED" :
        (isFinishing() ? "P302_LIFECYCLE_DESTROY_FINISH=OBSERVED" : "P302_LIFECYCLE_DESTROY_OTHER=OBSERVED"));
    // Process/activity recreation and cancellation must not leak a host FD.
    releaseHeldReader();
    if(bound){unbindService(conn);bound=false;}
    super.onDestroy();
  }
}
