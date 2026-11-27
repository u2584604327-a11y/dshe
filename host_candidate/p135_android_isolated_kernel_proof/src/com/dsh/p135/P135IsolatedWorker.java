package com.dsh.p135;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.system.Os;
import com.dsh.android.p134.P134RealArm64Gate;
import java.util.Arrays;

/** Deliberately powerless, non-exported Android isolated worker.
 * Does NOT open files, load a library, spawn a process, use network or run Node.
 */
public final class P135IsolatedWorker extends Service {
  static final int READ_ONLY_PROBE=135;
  private boolean answered;
  private final Messenger endpoint=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message request) {
      if(answered||request.what!=READ_ONLY_PROBE||request.replyTo==null)return;
      if(request.sendingUid!=getApplicationInfo().uid)return;
      answered=true;
      final boolean isolated=Process.isIsolated();
      final int uid=Process.myUid();
      final String machine=Os.uname().machine;
      final boolean guestArm64=Arrays.asList(Build.SUPPORTED_ABIS).contains("arm64-v8a");
      final boolean kernelX86="x86_64".equals(machine);
      final boolean gateAllowed=P134RealArm64Gate.allow(
          isolated,Build.VERSION.SDK_INT,Build.SUPPORTED_ABIS,machine);
      Bundle payload=new Bundle();
      payload.putInt("uid",uid);
      payload.putBoolean("isolated",isolated);
      payload.putBoolean("x86Kernel",kernelX86);
      payload.putBoolean("guestArm64Advertised",guestArm64);
      payload.putBoolean("realArm64GateAllowed",gateAllowed);
      // The host receives booleans only. No private file path, username,
      // environment variable, raw OS identity, user data or socket.
      Message reply=Message.obtain(null,READ_ONLY_PROBE);
      reply.setData(payload);
      try{request.replyTo.send(reply);}catch(RemoteException ignored){}
    }
  });
  @Override public IBinder onBind(Intent intent){
    if(!Process.isIsolated())throw new SecurityException("P135_ISOLATED_ONLY");
    return endpoint.getBinder();
  }
}
