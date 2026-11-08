package com.dsh.android.p200;

import android.app.Activity;
import android.app.Application;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.Log;
import com.dsh.android.p150.P150OriginalCoroutineObserver;
import com.dsh.android.p151.P151OriginalEngineStateSampler;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * P200 strictly passive original MainActivity lifecycle observation.
 * Runs only inside disposable CI same-package v138-derived test APK.
 * Does not invoke original EngineManager.start/probeBoot/config, P40, Node,
 * Binder, browser, any native tools, or third-party network.
 */
public final class P200OriginalStartupWindow {
  private static final String TAG="P200_PRELAUNCH";
  private static Window current;
  private P200OriginalStartupWindow(){}

  private static void emit(String code){Log.i(TAG,code);}
  private static final class Window implements Application.ActivityLifecycleCallbacks {
    final Activity probeActivity;
    final Application app;
    final Handler main = new Handler(Looper.getMainLooper());
    final String originalLauncherClass;
    final int baselineOriginal,baselineOther,uid,pid;
    int lastOriginal,lastOther;
    boolean mainCreated,mainResumed,ended,originalHint,otherHint;
    // Strictly category-only second-onCreate triage; never accepts a duplicate.
    Activity firstOriginal;
    boolean firstOriginalDestroyed,firstOriginalStateSaved,firstOriginalStopped;
    int samples;
    Object preExistingSingleton; // may be null; main app may instantiate it later.
    Object observedSingleton;
    boolean sawSingleton;
    Window(Activity a,String launcher) {
      probeActivity=a;app=a.getApplication();originalLauncherClass=launcher;
      uid=Process.myUid();pid=Process.myPid();
      baselineOriginal=P150OriginalCoroutineObserver.observedOriginal();
      baselineOther=P150OriginalCoroutineObserver.observedOther();
      lastOriginal=baselineOriginal;lastOther=baselineOther;
      preExistingSingleton=existingEngine(a);
    }
    boolean valid(){
      return !ended && !Process.isIsolated() && uid==Process.myUid() &&
          pid==Process.myPid() && !probeActivity.isDestroyed() &&
          !probeActivity.isFinishing();
    }
    boolean match(Activity a){
      return a!=null && a!=probeActivity &&
          originalLauncherClass.equals(a.getClass().getName()) &&
          a.getApplication()==app && !Process.isIsolated() &&
          uid==Process.myUid() && pid==Process.myPid();
    }
    void fail(String reason){emit("P200_"+reason+"=DENY");finish();}
    void finish(){ended=true;app.unregisterActivityLifecycleCallbacks(this);}
    void updateCounters(){
      int o=P150OriginalCoroutineObserver.observedOriginal();
      int x=P150OriginalCoroutineObserver.observedOther();
      if(o<lastOriginal || x<lastOther){
        fail("STACK_COUNTER_REWOUND");return;
      }
      originalHint |= o>baselineOriginal;
      otherHint |= x>baselineOther;
      lastOriginal=o;lastOther=x;
    }
    void snapshot(String stage){
      if(!valid()){fail("OWNER_ACTIVITY_OR_UID_PID_CHANGED");return;}
      updateCounters();
      if(ended)return;
      Object engine=existingEngine(probeActivity);
      String singleton;
      if(engine==null)singleton="MISSING";
      else if(!sawSingleton){
        observedSingleton=engine;sawSingleton=true;
        singleton=preExistingSingleton==null?"CREATED_AFTER_BASELINE":"EXISTING_AT_BASELINE";
        if(preExistingSingleton!=null && preExistingSingleton!=engine){
          fail("ENGINE_SINGLETON_REPLACED");return;
        }
      }else if(engine==observedSingleton)singleton="SAME";
      else{fail("ENGINE_SINGLETON_REPLACED");return;}
      String state=P151OriginalEngineStateSampler.sample().state;
      if(!("IDLE".equals(state)||"EXTRACTING".equals(state)||
           "STARTING".equals(state)||"READY".equals(state)||
           "FAILED".equals(state)||"DEAD".equals(state)||
           "UNRECOGNIZED_STATE".equals(state)||"MISSING".equals(state)||
           "UNREADABLE".equals(state))){
        fail("UNEXPECTED_STATE_CATEGORY");return;
      }
      emit("P200_"+stage+"_SINGLETON="+singleton);
      emit("P200_"+stage+"_STATE="+state);
      emit("P200_"+stage+"_ORIGINAL_STACK_DELTA="+
          (lastOriginal>baselineOriginal?"OBSERVED_NON_AUTHORITATIVE":"NOT_OBSERVED"));
      emit("P200_"+stage+"_SYNTHETIC_STACK_DELTA="+
          (lastOther>baselineOther?"YES":"NO"));
      emit("P200_"+stage+"=PASS");
    }
    @Override public void onActivityCreated(Activity activity,Bundle state){
      if(!match(activity))return;
      if(mainCreated){
        final String kind=(activity==firstOriginal)?"SAME_JAVA_INSTANCE":
            firstOriginalDestroyed?"RECREATED_AFTER_DESTROY":
            "NEW_WHILE_OLD_ALIVE";
        emit("P200_DUPLICATE_CREATE_KIND="+kind);
        emit("P200_DUPLICATE_CREATE_OLD_STATE_SAVED="+
             (firstOriginalStateSaved?"YES":"NO"));
        emit("P200_DUPLICATE_CREATE_OLD_STOPPED="+
             (firstOriginalStopped?"YES":"NO"));
        // Do not normalize, ignore, retry or deem this lifecycle valid.
        fail("ORIGINAL_LAUNCHER_DUPLICATE_CREATE");return;
      }
      if(!valid()){fail("PRELAUNCH_OWNER_REVOKED");return;}
      firstOriginal=activity;
      mainCreated=true;
      emit("P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONCREATE=PASS");
      snapshot("AFTER_ORIGINAL_ONCREATE");
    }
    @Override public void onActivityResumed(Activity activity){
      if(!match(activity) || ended)return;
      if(!mainCreated){fail("ORIGINAL_RESUME_WITHOUT_CREATE");return;}
      if(mainResumed){fail("ORIGINAL_DUPLICATE_RESUME");return;}
      mainResumed=true;
      emit("P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONRESUME=PASS");
      snapshot("AFTER_ORIGINAL_ONRESUME");
      for(final int t:new int[]{0,2,5,10}){
        main.postDelayed(()->{
          if(ended)return;
          snapshot("POST_RESUME_T"+t+"S");
          if(ended)return;
          samples++;
          if(t==10){
            if(samples!=4){fail("PASSIVE_SAMPLES_INCOMPLETE");return;}
            emit("P200_ORIGINAL_START_PRELAUNCH_TO_10S="+
                (originalHint?"OBSERVED_NON_AUTHORITATIVE":"NOT_OBSERVED"));
            emit("P200_SYNTHETIC_P43_BRIDGE=NOT_INVOKED");
            emit("P200_OS_COROUTINE_PROVENANCE=NOT_ATTESTED");
            emit("P200_ORIGINAL_PROCESS_READER_LATCH_PARITY=NOT_ATTESTED");
            emit("P200_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED");
            emit("P200_FOUR_POST_RESUME_PASSIVE_SAMPLES=PASS");
            finish();
          }
        },t*1000L);
      }
    }
    @Override public void onActivityStarted(Activity activity){}
    @Override public void onActivityPaused(Activity activity){}
    @Override public void onActivityStopped(Activity activity){
      if(activity==firstOriginal && mainCreated && !ended)firstOriginalStopped=true;
    }
    @Override public void onActivitySaveInstanceState(Activity activity,Bundle state){
      if(activity==firstOriginal && mainCreated && !ended)firstOriginalStateSaved=true;
    }
    @Override public void onActivityDestroyed(Activity activity){
      if(activity==firstOriginal && mainCreated && !ended)firstOriginalDestroyed=true;
      if(activity==probeActivity && !ended)fail("OBSERVER_DESTROYED_BEFORE_COMPLETE");
      else if(match(activity) && !mainResumed && !ended)
        fail("ORIGINAL_LAUNCHER_DESTROYED_BEFORE_RESUME");
    }
  }

  private static Object existingEngine(Activity a){
    try{
      Class<?> cls=Class.forName("com.dsh.android.EngineManager",false,a.getClassLoader());
      Field f=cls.getDeclaredField("instance");
      if(!Modifier.isStatic(f.getModifiers())||f.getType()!=cls)return null;
      f.setAccessible(true);
      return f.get(null);
    }catch(Throwable unavailable){return null;}
  }
  public static synchronized void arm(Activity activity){
    if(activity==null ||
       !"com.dsh.android".equals(activity.getPackageName()) ||
       !"com.dsh.android.p43.P43ProbeActivity".equals(activity.getClass().getName()) ||
       activity.isFinishing()||activity.isDestroyed()||Process.isIsolated() ||
       Looper.myLooper()!=Looper.getMainLooper()){
      emit("P200_DISPOSABLE_HOST_REQUIREMENT=DENY");return;
    }
    if(current!=null){
      emit("P200_DUPLICATE_PRELAUNCH_OBSERVER=DENY");return;
    }
    Intent launch=activity.getPackageManager().getLaunchIntentForPackage(
        activity.getPackageName());
    ComponentName target=launch==null?null:launch.getComponent();
    if(target==null || !activity.getPackageName().equals(target.getPackageName()) ||
       target.getClassName().equals(activity.getClass().getName())){
      emit("P200_ORIGINAL_LAUNCHER_UNRESOLVED=DENY");return;
    }
    Window p=new Window(activity,target.getClassName());
    current=p;
    p.app.registerActivityLifecycleCallbacks(p);
    p.snapshot("BEFORE_ORIGINAL_LAUNCH");
    if(p.ended)return;
    emit("P200_PRELAUNCH_BASELINE_BEFORE_MAIN_ACTIVITY=PASS");
    emit("P200_PRELAUNCH_ACTUAL_HOST_UID_PID=PASS");
    emit("P200_NO_ORIGINAL_ENGINE_START_OR_NODE_INVOKED=PASS");
  }
  public static synchronized void cancel(Activity activity){
    if(current!=null && current.probeActivity==activity && !current.ended)
      current.fail("TEST_OWNER_DESTROYED");
  }
}
