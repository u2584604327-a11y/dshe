package com.dsh.b1probe;

import android.app.Activity;
import android.app.Application;
import android.content.*;
import android.os.*;
import android.os.Process;
import android.util.Log;

/** B2 real two-live-process Binder test; not cross-UID access control. */
final class ConcurrentHarness {
  private final Activity host;
  private final Handler handler=new Handler(Looper.getMainLooper());
  private final Remote[] remote=new Remote[2];
  private final boolean[] ready=new boolean[2],written=new boolean[2],verified=new boolean[2];
  private final int[] pid=new int[2];
  private boolean finished;
  private int stage; // 0 startup, 2 writes, 3 verifies, 4 done
  ConcurrentHarness(Activity activity){host=activity;}
  private final class Remote implements ServiceConnection {
    final int index;
    final Class<?> clazz;
    final Messenger replies;
    Messenger service;
    boolean bound;
    Remote(int index,Class<?> clazz){
      this.index=index;this.clazz=clazz;
      replies=new Messenger(new Handler(Looper.getMainLooper(),m->receive(index,m)));
    }
    @Override public void onServiceConnected(ComponentName name,IBinder binder){
      if(finished)return;
      if(!name.getClassName().equals(clazz.getName())){deny("SERVICE_IDENTITY");return;}
      service=new Messenger(binder);
      send(this,ConcurrentSlotService.INIT);
    }
    @Override public void onServiceDisconnected(ComponentName name){
      if(!finished)deny("BINDER_DISCONNECTED");
    }
  }
  void start(){
    if(!host.getPackageName().equals(Application.getProcessName())){
      deny("CONTROLLER_PROCESS");return;
    }
    handler.postDelayed(()->{if(!finished)deny("TIMEOUT");},28000);
    remote[0]=new Remote(0,ConcurrentSlotAService.class);
    remote[1]=new Remote(1,ConcurrentSlotBService.class);
    for(Remote r:remote){
      r.bound=host.bindService(new Intent(host,r.clazz),r,Context.BIND_AUTO_CREATE);
      if(!r.bound){deny("BIND");return;}
    }
  }
  private void send(Remote r,int action){
    if(finished||r.service==null){deny("MISSING_BINDER");return;}
    Message m=Message.obtain(null,action);
    m.replyTo=r.replies;
    try{r.service.send(m);}catch(RemoteException e){deny("IPC_SEND");}
  }
  private boolean receive(int i,Message m){
    if(finished)return true;
    if(m.arg1<=0||m.arg1==Process.myPid()||m.arg2!=Process.myUid()||
        (pid[i]!=0&&pid[i]!=m.arg1)){deny("OS_PID_UID");return true;}
    if(pid[i]==0)pid[i]=m.arg1;
    if(m.what==ConcurrentSlotService.DENY){deny("SLOT_CHECK");return true;}
    if(stage==0&&m.what==ConcurrentSlotService.READY&&!ready[i]){
      ready[i]=true;
      if(ready[0]&&ready[1]){
        if(pid[0]==pid[1]){deny("SAME_PROCESS");return true;}
        Log.i("B1_PROBE","B2_ANDROID35_DISTINCT_LIVE_PIDS_SAME_APP_UID=PASS");
        stage=2;
        for(Remote r:remote)send(r,ConcurrentSlotService.WRITE);
      }
    }else if(stage==2&&m.what==ConcurrentSlotService.WRITTEN&&!written[i]){
      written[i]=true;
      if(written[0]&&written[1]){
        stage=3;
        for(Remote r:remote)send(r,ConcurrentSlotService.VERIFY);
      }
    }else if(stage==3&&m.what==ConcurrentSlotService.VERIFIED&&!verified[i]){
      verified[i]=true;
      if(verified[0]&&verified[1]){
        stage=4;
        Log.i("B1_PROBE","B2_ANDROID35_LIVE_A_B_COOKIE_LOCALSTORAGE_INDEXEDDB=PASS");
        Log.i("B1_PROBE","B2_ANDROID35_OS_USER_OR_VM=NOT_ATTESTED");
        close();
        host.finish();
      }
    }else deny("IPC_ORDER_REPLAY");
    return true;
  }
  private void deny(String reason){
    if(finished)return;
    Log.i("B1_PROBE","B1_ANDROID35_B2_"+reason+"=DENY");
    close();
    host.finish();
  }
  void close(){
    if(finished)return;
    finished=true;
    for(Remote r:remote)if(r!=null&&r.bound){
      try{host.unbindService(r);}catch(IllegalArgumentException ignored){}
      r.bound=false;
    }
  }
}
