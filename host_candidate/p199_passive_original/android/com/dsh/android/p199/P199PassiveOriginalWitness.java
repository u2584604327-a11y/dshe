package com.dsh.android.p199;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.util.Log;
import com.dsh.android.p150.P150OriginalCoroutineObserver;
import com.dsh.android.p151.P151OriginalEngineStateSampler;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * P199 disposable Android35-original-package passive observer.
 * Never calls original EngineManager.start, P40, Node, P75, Binder or user
 * browser APIs. May only sample existing object identity, StateFlow state
 * category and P150 stack-shape-only counters. Not a runtime permission.
 */
public final class P199PassiveOriginalWitness {
  private static final String TAG="P199_PASSIVE";
  private static final int[] MS={0,2000,5000,10000};
  private static Probe current;
  private P199PassiveOriginalWitness(){}

  static final class Probe {
    final Activity owner;
    final Handler handler=new Handler(Looper.getMainLooper());
    final int originalBaseline,otherBaseline,expectedUid,expectedPid;
    final Object originalInstance;
    boolean done,stopped,originalHint;
    int samples;
    Probe(Activity activity,Object existing){
      owner=activity;originalInstance=existing;
      originalBaseline=P150OriginalCoroutineObserver.observedOriginal();
      otherBaseline=P150OriginalCoroutineObserver.observedOther();
      expectedUid=Process.myUid();expectedPid=Process.myPid();
    }
    void mark(String code){Log.i(TAG,code);}
    void stop(){stopped=true;}
    String originalPointerStatus(){
      try{
        Class<?> c=Class.forName("com.dsh.android.EngineManager",false,owner.getClassLoader());
        Field instance=c.getDeclaredField("instance");
        if(!Modifier.isStatic(instance.getModifiers()) || instance.getType()!=c)
          return "UNREADABLE";
        instance.setAccessible(true);
        Object now=instance.get(null);
        return now==null?"MISSING":(now==originalInstance?"SAME":"CHANGED");
      }catch(Throwable inaccessible){return "UNREADABLE";}
    }
    String processPresence(){
      try{
        Class<?> c=Class.forName("com.dsh.android.EngineManager",false,owner.getClassLoader());
        Field process=c.getDeclaredField("process");
        if(Modifier.isStatic(process.getModifiers()) ||
           !java.lang.Process.class.isAssignableFrom(process.getType()))
          return "UNREADABLE";
        process.setAccessible(true);
        Object now=process.get(originalInstance);
        return now==null?"NULL":"NON_NULL";
      }catch(Throwable inaccessible){return "UNREADABLE";}
    }
    void sample(int which){
      if(stopped||done)return;
      if(owner.isFinishing()||owner.isDestroyed()||
         Process.isIsolated()||expectedUid!=Process.myUid()||
         expectedPid!=Process.myPid()){
        mark("P199_OWNER_PROCESS_OR_ACTIVITY_CHANGED=DENY");
        stop();return;
      }
      String pointer=originalPointerStatus();
      if(!"SAME".equals(pointer)){
        mark("P199_ORIGINAL_SINGLETON_POINTER_NOT_STABLE=DENY");
        stop();return;
      }
      P151OriginalEngineStateSampler.Sample state=
          P151OriginalEngineStateSampler.sample();
      // Only fixed enum categories escape. Never print failure text, URLs,
      // argv, paths, model content, session or Java object identities.
      String stateName=state.state;
      if(!("IDLE".equals(stateName)||"EXTRACTING".equals(stateName)||
           "STARTING".equals(stateName)||"READY".equals(stateName)||
           "FAILED".equals(stateName)||"DEAD".equals(stateName)||
           "UNRECOGNIZED_STATE".equals(stateName)||"UNREADABLE".equals(stateName)||
           "MISSING".equals(stateName))){
        mark("P199_UNALLOWLISTED_ENGINE_STATE=DENY");stop();return;
      }
      int original=P150OriginalCoroutineObserver.observedOriginal();
      int other=P150OriginalCoroutineObserver.observedOther();
      if(original<originalBaseline || other<otherBaseline){
        mark("P199_STACK_COUNTER_NON_MONOTONIC=DENY");stop();return;
      }
      if(original>originalBaseline)originalHint=true;
      mark("P199_SAMPLE_"+which+"_ENGINE_STATE="+stateName);
      mark("P199_SAMPLE_"+which+"_PROCESS_FIELD="+processPresence());
      mark("P199_SAMPLE_"+which+"_EXACT_SINGLETON=SAME");
      mark("P199_SAMPLE_"+which+"_ORIGINAL_STACK_HINT="+
           (original>originalBaseline?"PRESENT":"NOT_SEEN"));
      mark("P199_SAMPLE_"+which+"_OTHER_STACK_CHANGED="+
           (other>otherBaseline?"YES":"NO"));
      mark("P199_SAMPLE_"+which+"=PASS");
      samples++;
      if(which==3){
        if(samples!=MS.length){
          mark("P199_MISSING_PASSIVE_SAMPLE=DENY");stop();return;
        }
        done=true;
        mark("P199_REAL_COROUTINE_STACK_SHAPE="+
             (originalHint?"OBSERVED_NON_AUTHORITATIVE":"NOT_OBSERVED"));
        mark("P199_REAL_ORIGINAL_COROUTINE_OS_PROVENANCE=NOT_ATTESTED");
        mark("P199_PROCESS_READER_LATCH_STATEFLOW_RUNTIME_PARITY=NOT_ATTESTED");
        mark("P199_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED");
        mark("P199_FOUR_BOUNDED_PASSIVE_SAMPLES=PASS");
      }
    }
  }

  private static Object originalExistingInstance(Activity a) {
    try{
      Class<?> cls=Class.forName("com.dsh.android.EngineManager",false,a.getClassLoader());
      Field f=cls.getDeclaredField("instance");
      if(!Modifier.isStatic(f.getModifiers()) || f.getType()!=cls)
        return null;
      f.setAccessible(true);
      return f.get(null);
    }catch(Throwable denied){return null;}
  }

  public static synchronized void start(Activity a){
    if(a==null || !"com.dsh.android".equals(a.getPackageName()) ||
       !"com.dsh.android.p43.P43ProbeActivity".equals(a.getClass().getName()) ||
       a.isFinishing()||a.isDestroyed()||Process.isIsolated()||
       Looper.myLooper()!=Looper.getMainLooper()){
      Log.i(TAG,"P199_TEST_ONLY_HOST_PRECONDITION=DENY");return;
    }
    if(current!=null){
      Log.i(TAG,"P199_DUPLICATE_PASSIVE_PROBE=DENY");return;
    }
    Object existing=originalExistingInstance(a);
    if(existing==null){
      Log.i(TAG,"P199_EXISTING_ORIGINAL_SINGLETON_MISSING=DENY");return;
    }
    Probe p=new Probe(a,existing);
    current=p;
    p.mark("P199_EXISTING_ORIGINAL_SINGLETON_AND_REAL_HOST_UID_PID=PASS");
    p.mark("P199_P43_SYNTHETIC_P40_BRIDGE=NOT_INVOKED");
    for(int n=0;n<MS.length;n++){
      final int index=n;
      p.handler.postDelayed(()->p.sample(index),MS[n]);
    }
  }

  public static synchronized void cancel(Activity a){
    if(current!=null && current.owner==a)current.stop();
  }
}
