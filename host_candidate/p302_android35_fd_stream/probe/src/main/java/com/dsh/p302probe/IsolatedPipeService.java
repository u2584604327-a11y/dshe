package com.dsh.p302probe;

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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** One-use isolated-process, no-network synthetic FD read diagnosis. */
public final class IsolatedPipeService extends Service {
  public static final int REQUEST=1, REPLY=2;
  private static final String TAG="P302_WORKER";
  private static final byte[] EXPECTED=createExpected();
  private static byte[] createExpected() {
    byte[] data=new byte[65536];
    for(int i=0;i<data.length;i++)data[i]=(byte)((i*31+7)&255);
    return data;
  }
  public static final Set<String> FAILURES=Collections.unmodifiableSet(new HashSet<>(
    Arrays.asList("DENY_BAD_FRAME","DENY_EARLY_EOF","DENY_LENGTH",
      "DENY_READ_IO_ZERO","DENY_READ_IO_PARTIAL","DENY_READ_IO_EOF_CHECK",
      "DENY_READ_EOF_PEER_DEAD","DENY_READ_EOF_PEER_LEAKED",
      "DENY_READ_EOF_DETACHED","DENY_READ_EOF_REMOTE_ERROR",
      "DENY_READ_SECURITY","DENY_READ_RUNTIME","DENY_EXTRA_BYTES",
      "DENY_DESCRIPTOR_OPEN","DENY_WORKER_REPLAY")));
  private boolean consumed=false;
  private final Messenger messenger=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message msg) {
      if(msg.what!=REQUEST || msg.replyTo==null ||
          !Process.isIsolatedUid(Process.myUid()) ||
          msg.sendingUid!=getApplicationInfo().uid) {
        Log.i(TAG,"P302_DENY_BAD_SENDER=DENY");return;
      }
      if(consumed) {
        Log.i(TAG,"P302_WORKER_REPLAY_REJECTED=PASS");
        reply(msg.replyTo,"DENY_WORKER_REPLAY");
        return;
      }
      ParcelFileDescriptor fd;
      try {
        Bundle data=msg.getData();
        data.setClassLoader(ParcelFileDescriptor.class.getClassLoader());
        fd=data.getParcelable("fd",ParcelFileDescriptor.class);
      } catch(RuntimeException invalid) {
        Log.i(TAG,"P302_DENY_BAD_PARCEL=DENY");
        return;
      }
      if(fd==null) {
        Log.i(TAG,"P302_MISSING_FD_DENIED=PASS");
        reply(msg.replyTo,"DENY_MISSING_FD");
        return;
      }
      consumed=true;
      Log.i(TAG,"P302_WORKER_DESCRIPTOR_RECEIVED=PASS");
      String result=consume(fd);
      if(!"FD_PAYLOAD_OK".equals(result))
        Log.i(TAG,"P302_"+result+"=DENY");
      reply(msg.replyTo,result);
    }
  });
  private String consume(ParcelFileDescriptor fd) {
    int received=0;
    boolean equality=true;
    String phase="OPEN";
    try (ParcelFileDescriptor.AutoCloseInputStream in =
        new ParcelFileDescriptor.AutoCloseInputStream(fd)) {
      phase="READ";
      byte[] buf=new byte[4096];
      while(received<EXPECTED.length) {
        int n=in.read(buf,0,Math.min(buf.length,EXPECTED.length-received));
        if(n<0) return "DENY_EARLY_EOF";
        if(n==0)continue;
        for(int i=0;i<n;i++) {
          if(buf[i]!=EXPECTED[received+i]) equality=false;
        }
        received+=n;
      }
      Log.i(TAG,"P302_WORKER_EXACT_LENGTH_READ=PASS");
      if(!equality)return "DENY_BAD_FRAME";
      Log.i(TAG,"P302_WORKER_CONTENT_MATCHED=PASS");
      phase="EOF_CHECK";
      int end=in.read();
      if(end!=-1)return "DENY_EXTRA_BYTES";
      Log.i(TAG,"P302_WORKER_CLEAN_EOF=PASS");
      return "FD_PAYLOAD_OK";
    } catch(IOException io) {
      if("EOF_CHECK".equals(phase)) {
        // Strict fixed Android-framework categories; never log the exception
        // text, error payload, FD number, process UID or stack.
        if(io instanceof ParcelFileDescriptor.FileDescriptorDetachedException)
          return "DENY_READ_EOF_DETACHED";
        final String m=io.getMessage();
        if("Remote side is dead".equals(m))return "DENY_READ_EOF_PEER_DEAD";
        if("Remote side was leaked".equals(m))return "DENY_READ_EOF_PEER_LEAKED";
        if(m!=null && m.startsWith("Remote error: "))
          return "DENY_READ_EOF_REMOTE_ERROR";
        return "DENY_READ_IO_EOF_CHECK";
      }
      return received>0?"DENY_READ_IO_PARTIAL":"DENY_READ_IO_ZERO";
    } catch(SecurityException denied) {
      return "DENY_READ_SECURITY";
    } catch(RuntimeException runtime) {
      return "DENY_READ_RUNTIME";
    }
  }
  private void reply(Messenger to,String result) {
    Message m=Message.obtain(null,REPLY);
    Bundle data=new Bundle(); data.putString("result",result);m.setData(data);
    try {to.send(m);}
    catch(RemoteException ex) {Log.i(TAG,"P302_DENY_REPLY_TARGET_GONE=DENY");}
  }
  @Override public IBinder onBind(Intent intent){return messenger.getBinder();}
}
