package com.dsh.android.p43;
import android.app.Service;
import android.content.Intent;
import android.os.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
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
      // P45: receive ONLY one host-minted synthetic private asset as an
      // O_RDONLY file descriptor. No path, raw bytes, credentials, or
      // filesystem privilege is sent through Messenger. 64-byte hard cap.
      final ParcelFileDescriptor inputFd;
      try {
        inputFd=(ParcelFileDescriptor)data.getParcelable("p45_readonly_fd");
      } catch(RuntimeException invalid) {return;}
      if(inputFd==null || data.getInt("p45_max_bytes",-1)!=64)return;
      final byte[] content;
      try(InputStream reader=new ParcelFileDescriptor.AutoCloseInputStream(inputFd);
          ByteArrayOutputStream output=new ByteArrayOutputStream()) {
        byte[] chunk=new byte[32];int n;
        while((n=reader.read(chunk))!=-1) {
          if(n>64-output.size())return;
          output.write(chunk,0,n);
        }
        content=output.toByteArray();
      }catch(IOException invalidInput){return;}
      // This probe intentionally uses *synthetic*, public, non-user data.
      // Actual runtime file leasing and script approval are not enabled.
      byte[] expected="P45_SYNTHETIC_PRIVATE_ASSET_V1\\n".getBytes(StandardCharsets.UTF_8);
      if(!Arrays.equals(expected,content))return;
      final String assetHash;
      try {
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(content);
        StringBuilder b=new StringBuilder(64);
        for(byte v:hash)b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));
        assetHash=b.toString();
      }catch(Exception hashingFailure){return;}
      used=true;
      Bundle response=new Bundle();
      response.putString("session",session);
      response.putString("p44_profile_hash",profile.fingerprint());
      response.putBoolean("p44_is_real_virtual_machine",false);
      response.putBoolean("p44_hardware_identity_changed",false);
      response.putString("p45_asset_sha256",assetHash);
      response.putInt("p45_asset_size",content.length);
      response.putBoolean("p45_path_transferred",false);
      response.putBoolean("p45_root_used",false);
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
