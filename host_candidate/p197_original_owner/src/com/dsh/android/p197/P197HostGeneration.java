package com.dsh.android.p197;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Host-process-only generation ledger, NEVER an Android framework/OS attestor.
 * It must be fed solely by P197AndroidOwnerInspector reading an EXISTING
 * EngineManager.instance (no construction or start), Activity owner and
 * Android Process.myUid/myPid. It cannot authorize Node, arbitrary P75 start,
 * P47 bypass or a DEX coroutine merely because its data matches.
 */
public final class P197HostGeneration {
  private static final long MAX_LIFETIME_NANOS=12_000_000_000L;
  private static final AtomicLong NEXT_EPOCH=new AtomicLong();
  private static final Object LOCK=new Object();
  private static Lease current;

  private P197HostGeneration(){}

  /** Opaque identity-based lease, never serialized to Android Bundle/JS/HTTP. */
  public static final class Lease implements AutoCloseable {
    private final Object exactHost, originalEngineSingleton;
    private final String session;
    private final int hostUid, hostPid;
    private final long epoch, bornNanos;
    private boolean revoked;
    private Lease(Object host,Object engine,String s,int uid,int pid,long e){
      exactHost=host;originalEngineSingleton=engine;session=s;
      hostUid=uid;hostPid=pid;epoch=e;bornNanos=System.nanoTime();
    }
    public long ownerEpoch(){return epoch;}
    private boolean alive(Object host,Object engine,String s,int uid,int pid){
      long age=System.nanoTime()-bornNanos;
      return !revoked && age>=0 && age<=MAX_LIFETIME_NANOS &&
          exactHost==host && originalEngineSingleton==engine &&
          session.equals(s) && hostUid==uid && hostPid==pid;
    }
    /** Non-authorizing observation; caller must supply real framework UID. */
    public boolean isLive(Object host,Object engine,String s,int uid,int pid){
      synchronized(LOCK) {
        if(current!=this || !alive(host,engine,s,uid,pid)) {
          revokeUnderLock();
          return false;
        }
        return true;
      }
    }
    private void revokeUnderLock(){
      revoked=true;
      if(current==this)current=null;
    }
    @Override public void close(){
      synchronized(LOCK){revokeUnderLock();}
    }
    public boolean isRevoked(){
      synchronized(LOCK){return revoked;}
    }
  }

  public static Lease begin(Object originalHostActivity,Object existingOriginalEngine,
      String hostMintedSession,int actualHostUid,int actualHostPid){
    if(originalHostActivity==null || existingOriginalEngine==null ||
       originalHostActivity==existingOriginalEngine ||
       hostMintedSession==null || !hostMintedSession.matches("[0-9a-f]{64}") ||
       actualHostUid<=0 || actualHostPid<=0)
      throw new SecurityException("P197_ORIGINAL_HOST_IDENTITY_REQUIRED");
    synchronized(LOCK){
      if(current!=null)
        throw new SecurityException("P197_EXISTING_OWNER_GENERATION");
      long epoch=NEXT_EPOCH.incrementAndGet();
      if(epoch<=0)throw new SecurityException("P197_HOST_EPOCH_EXHAUSTED");
      current=new Lease(originalHostActivity,existingOriginalEngine,
          hostMintedSession,actualHostUid,actualHostPid,epoch);
      return current;
    }
  }
}
