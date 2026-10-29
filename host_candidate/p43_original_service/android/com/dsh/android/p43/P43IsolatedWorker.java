package com.dsh.android.p43;
import android.app.Service;
import android.content.Intent;
import android.os.*;
/**
 * P43 separate isolated-Service test inside original DSH APK only.
 * No Node, files, networking, credentials or capabilities.
 */
public final class P43IsolatedWorker extends Service {
  public static final int INIT=431, HELLO=432;
  private boolean used=false;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()) {
    @Override public void handleMessage(Message message) {
      if(message.what!=INIT || used || !android.os.Process.isIsolated() ||
         message.replyTo==null ||
         message.sendingUid!=getApplicationInfo().uid) return;
      Bundle data=message.getData();
      String session=data.getString("session");
      if(session==null || !session.matches("[a-f0-9]{64}"))return;
      // The profile is only a simulated view. A syntactically malformed,
      // noncanonical or unexpectedly privileged profile fails closed.
      final P44VirtualDeviceProfile profile;
      try {
        profile=P44VirtualDeviceProfile.parse(data.getString("p44_profile"));
      } catch(RuntimeException invalidProfile) { return; }
      if(profile.canMakeSystemVirtualMachine() ||
         profile.altersRealHardwareIdentity() ||
         profile.grantsNetworkOrFilesystemAccess() ||
         profile.hasIndependentKernel())return;
      used=true;
      Bundle response=new Bundle();
      response.putString("session",session);
      response.putString("p44_profile_hash",profile.fingerprint());
      response.putBoolean("p44_is_real_virtual_machine",false);
      response.putBoolean("p44_hardware_identity_changed",false);
      Message reply=Message.obtain(null,HELLO);
      reply.setData(response);
      try {message.replyTo.send(reply);} catch(RemoteException ignored){}
    }
  });
  @Override public IBinder onBind(Intent intent){
    if(!android.os.Process.isIsolated())throw new SecurityException("P43_ISOLATED_ONLY");
    return inbox.getBinder();
  }
}
