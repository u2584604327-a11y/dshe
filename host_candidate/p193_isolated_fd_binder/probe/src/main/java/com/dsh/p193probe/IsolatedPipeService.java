package com.dsh.p193probe;

import android.app.Service;
import android.content.Intent;
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
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** One-purpose isolated synthetic FD probe. Never Node, WebView, or user data. */
public final class IsolatedPipeService extends Service {
  public static final int REQUEST=1, REPLY=2;
  private static final String TAG="P193_WORKER";
  private final Messenger service=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg) {
      if(msg.what!=REQUEST || msg.replyTo==null ||
         !Process.isIsolatedUid(Process.myUid()) ||
         msg.sendingUid!=getApplicationInfo().uid) {
        Log.i(TAG,"P193_DENY_BAD_SENDER=DENY");return;
      }
      ParcelFileDescriptor fd;
      try {
        Bundle data=msg.getData();
        data.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
        fd=data.getParcelable("fd",ParcelFileDescriptor.class);
      }catch(RuntimeException invalid){
        Log.i(TAG,"P193_DENY_BAD_PARCEL=DENY");return;
      }
      if(fd==null){ respond(msg.replyTo,"DENY_MISSING_FD");return; }
      String status="DENY_BAD_FRAME";
      try(ParcelFileDescriptor.AutoCloseInputStream in=
            new ParcelFileDescriptor.AutoCloseInputStream(fd)){
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        byte[] bytes=new byte[8];
        int n;
        while((n=in.read(bytes))!=-1){
          if(buffer.size()+n>32)break;
          buffer.write(bytes,0,n);
        }
        if(buffer.size()==14 &&
          "P193_SYNTHETIC".equals(new String(buffer.toByteArray(),StandardCharsets.US_ASCII))){
          status="FD_PAYLOAD_OK";
          Log.i(TAG,"P193_WORKER_ISOLATED_FD_READ=PASS");
        }
      }catch(Exception fail){status="DENY_FD_READ";}
      respond(msg.replyTo,status);
    }
  });
  private void respond(Messenger to,String status){
    Message m=Message.obtain(null,REPLY);
    Bundle b=new Bundle();b.putString("result",status);m.setData(b);
    try{to.send(m);}catch(RemoteException failed){
      Log.i(TAG,"P193_DENY_REPLY_TARGET_GONE=DENY");
    }
  }
  @Override public IBinder onBind(Intent intent){return service.getBinder();}
}
