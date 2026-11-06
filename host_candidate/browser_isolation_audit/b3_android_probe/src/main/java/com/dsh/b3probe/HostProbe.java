package com.dsh.b3probe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import com.dsh.b3.B3SlotCommandGate;
import com.dsh.b3.B3SlotCommandGate.*;
import java.util.IdentityHashMap;

/**
 * Standalone disposable Android35 proof. No WebView, DSH account data or production wiring.
 * Binder UID is read synchronously in the actual transaction, never in Handler/message fields.
 */
public final class HostProbe extends Activity {
  public static final String HOST_DESCRIPTOR="com.dsh.b3probe.HOST_GATE_V1";
  public static final String SLOT_DESCRIPTOR="com.dsh.b3probe.SLOT_V1";
  public static final int REQUEST=100, RESULT=101, INSTALL=200, FORWARD=201;
  public static final int UID_DENIED=-2, CAP_DENIED=-3, MALFORMED=-4;
  static volatile HostGate GATE;
  private final IBinder[] remote=new IBinder[2];
  private boolean started,failed;
  private final ServiceConnection[] binds=new ServiceConnection[2];

  public static final class HostGate extends Binder {
    private final B3SlotCommandGate policy=new B3SlotCommandGate();
    private final IdentityHashMap<IBinder,Session> granted=new IdentityHashMap<>();
    private final int[] lastPid={0,0};
    private boolean sawTrustedUid;
    private static final class Session {
      final Slot slot;
      final long epoch;
      final Lease lease;
      Ticket ticket;
      Session(Slot slot,long epoch,Lease lease){
        this.slot=slot;this.epoch=epoch;this.lease=lease;
      }
    }
    synchronized IBinder activate(Slot slot,long epoch,long ttl){
      Lease lease=policy.activate(slot,epoch,SystemClock.elapsedRealtime(),ttl);
      IBinder capability=new Binder();
      granted.put(capability,new Session(slot,epoch,lease));
      return capability;
    }
    synchronized void revoke(Slot slot){policy.revoke(slot);}
    synchronized boolean topologyProved(){
      return sawTrustedUid&&lastPid[0]>0&&lastPid[1]>0&&
          lastPid[0]!=lastPid[1]&&lastPid[0]!=Process.myPid()&&
          lastPid[1]!=Process.myPid();
    }
    @Override protected synchronized boolean onTransact(
        int tx, Parcel data, Parcel reply, int flags) throws RemoteException {
      if(tx!=REQUEST&&tx!=RESULT)return super.onTransact(tx,data,reply,flags);
      // Must happen before any Handler post, identity clearing or payload parsing.
      final int trustedUid=Binder.getCallingUidOrThrow();
      final int observedPid=Binder.getCallingPid(); // diagnostic only, never authorization
      int answer;
      if(trustedUid!=Process.myUid() || observedPid==Process.myPid()){
        answer=UID_DENIED;
      } else {
        sawTrustedUid=true;
        try {
          data.enforceInterface(HOST_DESCRIPTOR);
          IBinder capability=data.readStrongBinder();
          int slotId=data.readInt();
          long epoch=data.readLong();
          long seq=data.readLong();
          int opOrdinal=data.readInt();
          if(data.dataAvail()>2048) {
            answer=MALFORMED;
          } else {
            byte[] payload=data.createByteArray();
            if(data.dataAvail()!=0||payload==null||slotId<0||slotId>1){
              answer=MALFORMED;
            } else {
              Session session=granted.get(capability);
              if(session==null) {
                answer=CAP_DENIED;
              } else {
                if(slotId==session.slot.ordinal())lastPid[slotId]=observedPid;
                if(opOrdinal<0||opOrdinal>=Op.values().length) {
                  answer=Code.ACTION_DENIED.ordinal();
                } else if(tx==REQUEST){
                  Decision decision=policy.command(session.lease,Slot.values()[slotId],
                      epoch,seq,Op.values()[opOrdinal],payload.length,SystemClock.elapsedRealtime());
                  if(decision.code==Code.ACCEPT)session.ticket=decision.ticket;
                  answer=decision.code.ordinal();
                } else {
                  answer=policy.result(session.lease,session.ticket,Slot.values()[slotId],
                      epoch,seq,Op.values()[opOrdinal],payload.length,SystemClock.elapsedRealtime()).ordinal();
                }
              }
            }
          }
        } catch(RuntimeException invalid) {
          answer=MALFORMED;
        }
      }
      reply.writeNoException();
      reply.writeInt(answer);
      return true;
    }
  }

  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    if(state!=null || GATE!=null){fail();return;}
    GATE=new HostGate();
    Class<?>[] classes={SlotService.A.class,SlotService.B.class};
    for(int i=0;i<2;i++){
      final int slot=i;
      binds[i]=new ServiceConnection(){
        @Override public void onServiceConnected(ComponentName name,IBinder binder){
          if(failed||!name.getClassName().equals(classes[slot].getName())){fail();return;}
          remote[slot]=binder;
          if(remote[0]!=null&&remote[1]!=null&&!started){
            started=true;
            new Thread(HostProbe.this::test,"b3-synthetic-verification").start();
          }
        }
        @Override public void onServiceDisconnected(ComponentName name){fail();}
      };
      if(!bindService(new Intent(this,classes[i]),binds[i],Context.BIND_AUTO_CREATE)){
        fail();return;
      }
    }
  }
  private void fail(){
    if(failed)return;
    failed=true;
    Log.i("B3_PROBE","B3_ANDROID35_GATE=DENY");
  }
  private static int code(Code c){return c.ordinal();}
  private int transact(int slot,int tx,IBinder gate,IBinder cap,int claim,
      long epoch,long seq,Op op,int size) throws RemoteException {
    Parcel d=Parcel.obtain(),r=Parcel.obtain();
    try{
      d.writeInterfaceToken(SLOT_DESCRIPTOR);
      if(tx==INSTALL){
        d.writeStrongBinder(gate);
        d.writeStrongBinder(cap);
        d.writeInt(claim);
      }else {
        d.writeInt(tx);
        d.writeInt(claim);
        d.writeLong(epoch);
        d.writeLong(seq);
        d.writeInt(op.ordinal());
        d.writeByteArray(new byte[size]);
      }
      if(!remote[slot].transact(tx==INSTALL?INSTALL:FORWARD,d,r,0))
        throw new RemoteException("B3_MISSING_SLOT_TRANSACTION");
      r.readException();
      return r.readInt();
    }finally{d.recycle();r.recycle();}
  }
  private void install(int slot,IBinder cap) throws RemoteException {
    require(0,transact(slot,INSTALL,GATE,cap,slot,0,0,Op.PROBE_STATUS,0));
  }
  private void require(int expected,int actual){
    if(expected!=actual)throw new IllegalStateException("B3_NEGATIVE_MISMATCH");
  }
  private void assertCall(int slot,int tx,int claim,long epoch,long seq,
      Op op,int size,int expected) throws RemoteException{
    require(expected,transact(slot,tx,null,null,claim,epoch,seq,op,size));
  }
  private void test(){
    try {
      IBinder capA=GATE.activate(Slot.A,101,12000);
      IBinder capB=GATE.activate(Slot.B,201,12000);
      install(0,capA);install(1,capB);
      assertCall(0,REQUEST,1,101,1,Op.PROBE_STATUS,1,code(Code.WRONG_SLOT));
      assertCall(1,REQUEST,0,201,1,Op.PROBE_STATUS,1,code(Code.WRONG_SLOT));
      assertCall(0,REQUEST,0,999,1,Op.PROBE_STATUS,1,code(Code.WRONG_EPOCH));
      assertCall(0,REQUEST,0,101,2,Op.PROBE_STATUS,1,code(Code.OUT_OF_ORDER));
      assertCall(0,REQUEST,0,101,1,Op.COOKIE_EXPORT,1,code(Code.ACTION_DENIED));
      assertCall(0,REQUEST,0,101,1,Op.PROBE_STATUS,257,code(Code.SIZE_DENIED));
      assertCall(0,REQUEST,0,101,1,Op.PROBE_STATUS,3,code(Code.ACCEPT));
      assertCall(0,REQUEST,0,101,1,Op.PROBE_STATUS,3,code(Code.REPLAY));
      assertCall(0,REQUEST,0,101,2,Op.PROBE_STATUS,3,code(Code.IN_FLIGHT));
      assertCall(0,RESULT,0,101,2,Op.PROBE_STATUS,1,code(Code.WRONG_TICKET));
      assertCall(0,RESULT,0,101,1,Op.READ_SYNTHETIC,1,code(Code.WRONG_RESULT_OP));
      assertCall(0,RESULT,0,101,1,Op.PROBE_STATUS,513,code(Code.RESULT_SIZE_DENIED));
      assertCall(0,RESULT,0,101,1,Op.PROBE_STATUS,3,code(Code.ACCEPT));
      assertCall(0,RESULT,0,101,1,Op.PROBE_STATUS,3,code(Code.RESULT_REPLAY));
      assertCall(1,REQUEST,1,201,1,Op.PROBE_STATUS,3,code(Code.ACCEPT));
      assertCall(1,RESULT,1,201,1,Op.PROBE_STATUS,3,code(Code.ACCEPT));
      assertCall(0,REQUEST,0,101,2,Op.PROBE_STATUS,1,code(Code.ACCEPT));
      GATE.revoke(Slot.A);
      assertCall(0,RESULT,0,101,2,Op.PROBE_STATUS,1,code(Code.REVOKED));
      assertCall(0,REQUEST,0,101,3,Op.PROBE_STATUS,1,code(Code.REVOKED));
      IBinder renewed=GATE.activate(Slot.A,102,12000);
      install(0,renewed);
      assertCall(0,REQUEST,0,101,1,Op.PROBE_STATUS,1,code(Code.WRONG_EPOCH));
      assertCall(0,REQUEST,0,102,1,Op.PROBE_STATUS,1,code(Code.ACCEPT));
      assertCall(0,RESULT,0,102,1,Op.PROBE_STATUS,1,code(Code.ACCEPT));
      assertCall(1,REQUEST,1,201,2,Op.PROBE_STATUS,1,code(Code.ACCEPT));
      assertCall(1,RESULT,1,201,2,Op.PROBE_STATUS,1,code(Code.ACCEPT));
      IBinder expired=GATE.activate(Slot.A,103,20);
      install(0,expired);
      Thread.sleep(90);
      assertCall(0,REQUEST,0,103,1,Op.PROBE_STATUS,1,code(Code.EXPIRED));
      install(0,new Binder());
      assertCall(0,REQUEST,0,104,1,Op.PROBE_STATUS,1,CAP_DENIED);
      if(!GATE.topologyProved())throw new IllegalStateException("B3_TOPOLOGY_NOT_PROVED");
      Log.i("B3_PROBE","B3_ANDROID35_TRANSACTION_UID_AND_DISTINCT_PROCESSES=PASS");
      Log.i("B3_PROBE","B3_ANDROID35_WRONG_SLOT_REPLAY_EPOCH_REVOKE=PASS");
      Log.i("B3_PROBE","B3_ANDROID35_BOUNDED_RESULT_ONE_SHOT=PASS");
      Log.i("B3_PROBE","B3_ANDROID35_HOST_CLOCK_AND_REAL_PAYLOAD_SIZE=PASS");
      Log.i("B3_PROBE","B3_ANDROID35_SHARED_UID_HOSTILE_PROCESS_ISOLATION=NOT_ATTESTED");
      Log.i("B3_PROBE","B3_ANDROID35_WORK_PROFILE_AVF=NOT_ATTESTED");
      Log.i("B3_PROBE","B3_ORIGINAL_DSH_AND_USER_DATA_TOUCHED=NO");
      Log.i("B3_PROBE","B3_V139_RELEASE=STRUCTURAL_BLOCKED");
    }catch(Exception e){fail();}
  }
  @Override protected void onDestroy(){
    for(int i=0;i<2;i++)if(binds[i]!=null)
      try{unbindService(binds[i]);}catch(IllegalArgumentException ignored){}
    GATE=null;
    super.onDestroy();
  }
}
