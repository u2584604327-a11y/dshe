package com.dsh.b3attacker;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

/** Independent Linux UID deliberately submits a forged-looking Binder transaction. */
public final class AttackerProbe extends Activity {
  private ServiceConnection connection;
  private boolean complete;
  private void fail(){
    if(complete)return;complete=true;
    Log.i("B3_PROBE","B3_ANDROID35_EXTERNAL_DIFFERENT_UID=DENY");
    finish();
  }
  @Override public void onCreate(Bundle saved){
    super.onCreate(saved);
    if(saved!=null){fail();return;}
    connection=new ServiceConnection(){
      @Override public void onServiceConnected(ComponentName name,IBinder host){
        new Thread(()->{
          Parcel data=Parcel.obtain(),reply=Parcel.obtain();
          try{
            data.writeInterfaceToken("com.dsh.b3probe.HOST_GATE_V1");
            data.writeStrongBinder(new Binder()); // unknown capability
            data.writeInt(0);
            data.writeLong(101);
            data.writeLong(1);
            data.writeInt(0);
            data.writeByteArray(new byte[4]);
            if(!host.transact(100,data,reply,0))throw new RemoteException();
            reply.readException();
            if(reply.readInt()!=-2)throw new SecurityException("UID_MUST_BE_DENIED");
            Log.i("B3_PROBE","B3_ANDROID35_EXTERNAL_DIFFERENT_UID_DENIED_IN_TRANSACTION=PASS");
            complete=true;
            runOnUiThread(AttackerProbe.this::finish);
          }catch(Exception e){runOnUiThread(AttackerProbe.this::fail);}
          finally{data.recycle();reply.recycle();}
        },"b3-different-uid-probe").start();
      }
      @Override public void onServiceDisconnected(ComponentName component){fail();}
    };
    Intent explicit=new Intent().setClassName(
        "com.dsh.b3probe","com.dsh.b3probe.HostGateService");
    if(!bindService(explicit,connection,Context.BIND_AUTO_CREATE))fail();
  }
  @Override protected void onDestroy(){
    if(connection!=null)try{unbindService(connection);}catch(IllegalArgumentException ignored){}
    super.onDestroy();
  }
}
