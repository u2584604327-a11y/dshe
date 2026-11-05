package com.dsh.android.p197;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Package-neutral identity and one-host-owner negative suite. No Android UID trust here. */
public final class P197HostGenerationTest {
  private static final String SESSION="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static int checks;
  private static void ok(boolean value,String tag){
    checks++;if(!value)throw new AssertionError("P197_"+tag);
  }
  private static void invalid(Runnable f,String tag){
    boolean denied=false;
    try{f.run();}catch(SecurityException expected){denied=true;}
    ok(denied,tag);
  }
  public static void main(String[] argv)throws Exception {
    ok(Modifier.isFinal(P197HostGeneration.class.getModifiers()),"FINAL_HOST_LEDGER");
    Constructor<?>[] constructors=P197HostGeneration.Lease.class.getDeclaredConstructors();
    ok(constructors.length==1 && Modifier.isPrivate(constructors[0].getModifiers()),
        "NO_PUBLIC_LEASE_FACTORY");

    Object originalActivity=new Object(), actualEngine=new Object();
    Object wrongEngine=new Object(), otherActivity=new Object();
    invalid(()->P197HostGeneration.begin(null,actualEngine,SESSION,10100,231),
            "NULL_ACTIVITY_DENIED");
    invalid(()->P197HostGeneration.begin(originalActivity,null,SESSION,10100,231),
            "MISSING_ORIGINAL_SINGLETON_DENIED");
    invalid(()->P197HostGeneration.begin(originalActivity,originalActivity,SESSION,10100,231),
            "FAKE_SINGLETON_ALIAS_DENIED");
    invalid(()->P197HostGeneration.begin(originalActivity,actualEngine,"user-supplied",10100,231),
            "BAD_SESSION_DENIED");
    invalid(()->P197HostGeneration.begin(originalActivity,actualEngine,SESSION,0,231),
            "MISSING_UID_DENIED");
    invalid(()->P197HostGeneration.begin(originalActivity,actualEngine,SESSION,10100,0),
            "MISSING_PID_DENIED");

    P197HostGeneration.Lease a=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    ok(a.ownerEpoch()>0,"POSITIVE_FIRST_EPOCH");
    ok(a.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "EXACT_HOST_ENGINE_SESSION_UID_PID_LIVE");
    invalid(()->P197HostGeneration.begin(originalActivity,actualEngine,SESSION,10100,231),
        "SECOND_OWNER_UNTIL_REVOKED_DENIED");
    // Wrong identity invalidates old generation even when string/session same.
    ok(!a.isLive(otherActivity,actualEngine,SESSION,10100,231),
        "ACTIVITY_REPLACEMENT_DENIED");
    ok(a.isRevoked(),"WRONG_ACTIVITY_BURNS_GENERATION");
    ok(!a.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "BURNED_EPOCH_NOT_REUSABLE");

    P197HostGeneration.Lease b=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    ok(b.ownerEpoch()>a.ownerEpoch(),"MONOTONIC_AFTER_REBIND");
    ok(!a.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "NO_OLD_EPOCH_ABA");
    ok(!b.isLive(originalActivity,wrongEngine,SESSION,10100,231),
        "ORIGINAL_SINGLETON_CHANGE_DENIED");
    ok(b.isRevoked(),"ENGINE_DRIFT_REVOKES");

    P197HostGeneration.Lease c=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    ok(!c.isLive(originalActivity,actualEngine,SESSION,10101,231),
        "DIFFERENT_FRAMEWORK_HOST_UID_DENIED");
    ok(c.isRevoked(),"HOST_UID_DRIFT_REVOKES");
    P197HostGeneration.Lease d=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    ok(!d.isLive(originalActivity,actualEngine,SESSION,10100,232),
        "HOST_PROCESS_RESTART_DENIED");
    ok(d.isRevoked(),"PID_DRIFT_REVOKES");
    P197HostGeneration.Lease e=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    String variant="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    ok(!e.isLive(originalActivity,actualEngine,variant,10100,231),
        "SESSION_REPLACEMENT_DENIED");
    ok(e.isRevoked(),"SESSION_DRIFT_REVOKES");
    P197HostGeneration.Lease f=P197HostGeneration.begin(originalActivity,actualEngine,
        SESSION,10100,231);
    f.close();
    ok(f.isRevoked(),"ACTIVITY_ON_DESTROY_REVOKES");
    ok(!f.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "CLOSED_LEASE_NEVER_RECOVERS");

    P197HostGeneration.Lease concurrent=P197HostGeneration.begin(originalActivity,
        actualEngine,SESSION,10100,231);
    CountDownLatch ready=new CountDownLatch(12),go=new CountDownLatch(1);
    AtomicInteger observed=new AtomicInteger(),notLive=new AtomicInteger();
    List<Thread> pool=new ArrayList<>();
    for(int i=0;i<12;i++){
      Thread t=new Thread(()->{
        ready.countDown();
        try{
          if(!go.await(3,TimeUnit.SECONDS))return;
          if(concurrent.isLive(originalActivity,actualEngine,SESSION,10100,231))
            observed.incrementAndGet();
          else notLive.incrementAndGet();
        }catch(InterruptedException ignored){Thread.currentThread().interrupt();}
      },"p197-observation-"+i);
      pool.add(t);t.start();
    }
    ok(ready.await(3,TimeUnit.SECONDS),"THREADS_READY");
    go.countDown();
    for(Thread t:pool)t.join(3000);
    ok(pool.stream().noneMatch(Thread::isAlive),"NO_UNBOUNDED_THREADS");
    ok(observed.get()==12 && notLive.get()==0,
        "EXACT_OWNER_MULTI_CALLBACK_OBSERVATION");
    concurrent.close();
    ok(!concurrent.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "BINDER_DEATH_INVALIDATES_ALL");

    P197HostGeneration.Lease newest=P197HostGeneration.begin(originalActivity,
        actualEngine,SESSION,10100,231);
    ok(newest.ownerEpoch()>concurrent.ownerEpoch(),"EPOCH_NEVER_REUSED_AFTER_DEATH");
    ok(newest.isLive(originalActivity,actualEngine,SESSION,10100,231),
        "FRESH_EPOCH_LIVE");
    newest.close();
    ok(newest.isRevoked(),"CLEANUP_CLOSED");

    System.out.println("P197_EXACT_ORIGINAL_OBJECT_AND_HOST_PROCESS_EPOCH=PASS");
    System.out.println("P197_OLD_SESSION_ACTIVITY_BINDER_DEATH_REVOKES=PASS");
    System.out.println("P197_CONCURRENT_OBSERVATIONS_NO_LEASE_RESURRECTION=PASS");
    System.out.println("P197_JAVA8_HOST_OWNER_NEGATIVES=PASS checks="+checks);
    System.out.println("P197_FRAMEWORK_UID_AND_ORIGINAL_SINGLETON_REAL_ANDROID=REQUIRES_ANDROID_TEST");
    System.out.println("P197_TRUE_ENGINE_MANAGER_COROUTINE=NOT_INVOKED");
    System.out.println("P197_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED");
  }
}
