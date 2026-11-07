package com.dsh.android.p197;

import android.app.Activity;
import android.os.Process;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * Android35 original-v138-derived P43 test ONLY. Read the existing real
 * EngineManager.instance pointer WITHOUT calling get/create/start or reading
 * state, argv, private data or original app files. Not original coroutine
 * authentication: it is a genuine existing-object + host UID/PID observation.
 */
public final class P197AndroidOwnerInspector implements AutoCloseable {
  private final Activity exactActivity;
  private final String session;
  private final Class<?> originalEngineClass;
  private final Field originalSingletonField;
  private final Object initialOriginalEngine;
  private final int hostUid,hostPid;
  private final P197HostGeneration.Lease lease;
  private boolean closed;

  public P197AndroidOwnerInspector(Activity activity,String hostSession) {
    if(activity==null || hostSession==null ||
       !hostSession.matches("[a-f0-9]{64}") ||
       !"com.dsh.android".equals(activity.getPackageName()) ||
       !"com.dsh.android.p43.P43ProbeActivity".equals(
           activity.getClass().getName()) ||
       activity.isFinishing() || activity.isDestroyed() ||
       Process.isIsolated())
      throw new SecurityException("P197_ONLY_DISPOSABLE_ORIGINAL_HOST_ACTIVITY");
    try {
      originalEngineClass=Class.forName("com.dsh.android.EngineManager",
          false,activity.getClassLoader());
      originalSingletonField=originalEngineClass.getDeclaredField("instance");
      if(!Modifier.isStatic(originalSingletonField.getModifiers()) ||
         originalSingletonField.getType()!=originalEngineClass)
        throw new SecurityException("P197_UNEXPECTED_ORIGINAL_SINGLETON_FIELD");
      originalSingletonField.setAccessible(true);
      initialOriginalEngine=originalSingletonField.get(null);
      if(initialOriginalEngine==null ||
         initialOriginalEngine.getClass()!=originalEngineClass)
        throw new SecurityException("P197_ORIGINAL_SINGLETON_NOT_ACTIVE");
    }catch(ReflectiveOperationException | LinkageError inaccessible) {
      throw new SecurityException("P197_ORIGINAL_SINGLETON_REFLECTION_DENIED");
    }
    exactActivity=activity;session=hostSession;
    hostUid=Process.myUid();hostPid=Process.myPid();
    lease=P197HostGeneration.begin(activity,initialOriginalEngine,
        session,hostUid,hostPid);
  }
  /**
   * Exact OS process and ORIGINAL singleton referential identity are
   * rechecked, never trusted from Intent/Bundle/JS/account data.
   */
  public synchronized boolean isLive() {
    if(closed || exactActivity.isFinishing() || exactActivity.isDestroyed() ||
       Process.isIsolated()) {
      close();return false;
    }
    try {
      Object now=originalSingletonField.get(null);
      if(!lease.isLive(exactActivity,now,session,Process.myUid(),Process.myPid())){
        close();return false;
      }
      return true;
    }catch(ReflectiveOperationException | LinkageError fail){
      close();return false;
    }
  }
  public synchronized long hostOwnerEpoch() {
    if(!isLive())throw new SecurityException("P197_REVOKED_ORIGINAL_HOST_OWNER");
    return lease.ownerEpoch();
  }
  @Override public synchronized void close(){
    if(!closed){closed=true;lease.close();}
  }
  public synchronized boolean isRevoked(){return closed || lease.isRevoked();}
}
