package com.dsh.android.engine;
import android.app.Service;import android.content.Intent;import android.os.*;
import com.dsh.android.p48.P48FixedIsolatedChild;
import com.dsh.android.p50.P50OriginalNodeFixedChild;
import com.dsh.android.p68.P68AndroidBinderIntake.WorkerPipes;
import java.io.IOException;

/** A single fixed HTTP-component test lease. Nonexported, isolated, no original
 * DSH context/data or arbitrary argv/path. Not a production registration. */
public final class OriginalHttpIsolatedService extends Service {
  private boolean used;private int hostUid;private String session;private long epoch,requestSeq;
  private P50OriginalNodeFixedChild child;
  private final Messenger inbox=new Messenger(new Handler(Looper.getMainLooper()){
    @Override public void handleMessage(Message message){
      if(message.sendingUid!=hostUid||!android.os.Process.isIsolated()||
          !"com.dsh.p51.networkprobe".equals(getPackageName()))return;
      Bundle data=message.getData();
      if(message.what==P48FixedIsolatedChild.START){
        if(used){stopChild();return;}used=true;
        WorkerPipes pipes=null;
        try{
          String claimed=data.getString("session");long issued=data.getLong("issued_ms"),now=SystemClock.elapsedRealtime();
          long generation=data.getLong("epoch");
          if(claimed==null||!claimed.matches("[0-9a-f]{64}")||generation<=0||issued<=0||
              now<issued||now-issued>12000||data.getLong("request_seq")!=1||message.replyTo==null)
            throw new SecurityException("HTTP_TEST_ONE_USE_LEASE");
          pipes=WorkerPipes.receive(data.getBundle("process_pipes"),message.sendingUid,hostUid);
          session=claimed;epoch=generation;requestSeq=1;
          child=P50OriginalNodeFixedChild.originalHttpServices(OriginalHttpIsolatedService.this,message.replyTo,session,pipes);
          child.start();
        }catch(IOException|RuntimeException denied){if(pipes!=null)pipes.close();stopChild();}
        return;
      }
      if(!used||session==null||!session.equals(data.getString("session"))||epoch!=data.getLong("epoch")||
          data.getLong("request_seq")!=requestSeq+1)return;
      if(message.what!=P48FixedIsolatedChild.STOP&&message.what!=P48FixedIsolatedChild.KILL)return;
      requestSeq++;
      if(child!=null)child.stop(message.what==P48FixedIsolatedChild.KILL);
    }
  });
  @Override public void onCreate(){super.onCreate();hostUid=getApplicationInfo().uid;}
  @Override public IBinder onBind(Intent intent){return inbox.getBinder();}
  private void stopChild(){if(child!=null)child.stop(true);}
  @Override public boolean onUnbind(Intent intent){stopChild();return false;}
  @Override public void onDestroy(){stopChild();super.onDestroy();}
}
