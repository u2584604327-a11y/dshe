package com.dsh.b3probe;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

/** No accounts, WebView or network; only forwarded host-issued test capabilities. */
public abstract class SlotService extends Service {
  private IBinder hostGate,capability;
  protected abstract int slotId();
  private final Binder entry=new Binder(){
    /** Disposable probe only: forward a real synthetic FD to prove that
     *  HostGate rejects it. The slot closes its temporary duplicate. */
    private int forwardSyntheticFd(Parcel data) throws RemoteException {
      try {
        data.enforceInterface(HostProbe.SLOT_DESCRIPTOR);
        if(hostGate==null||capability==null)return HostProbe.MALFORMED;
        int requestType=data.readInt(), claim=data.readInt();
        long epoch=data.readLong(),seq=data.readLong();
        int op=data.readInt();
        if(requestType!=HostProbe.REQUEST||data.dataAvail()>2048||
            !data.hasFileDescriptors())return HostProbe.MALFORMED;
        byte[] payload=data.createByteArray();
        try(ParcelFileDescriptor received=data.readFileDescriptor()){
          if(payload==null||received==null||data.dataAvail()!=0)
            return HostProbe.MALFORMED;
          Parcel d=Parcel.obtain(),r=Parcel.obtain();
          try{
            d.writeInterfaceToken(HostProbe.HOST_DESCRIPTOR);
            d.writeStrongBinder(capability);
            d.writeInt(claim);
            d.writeLong(epoch);
            d.writeLong(seq);
            d.writeInt(op);
            d.writeByteArray(payload);
            d.writeFileDescriptor(received.getFileDescriptor());
            if(!d.hasFileDescriptors())return HostProbe.MALFORMED;
            if(!hostGate.transact(requestType,d,r,0))
              throw new RemoteException("B3_FD_GATE_MISSING");
            r.readException();
            return r.readInt();
          }finally{d.recycle();r.recycle();}
        }
      }catch(java.io.IOException|RuntimeException invalid){
        return HostProbe.MALFORMED;
      }
    }
    @Override protected boolean onTransact(int tx,Parcel data,Parcel reply,int flags)
        throws RemoteException {
      if(tx==HostProbe.FD_FORWARD){
        int answer=forwardSyntheticFd(data);
        reply.writeNoException();reply.writeInt(answer);return true;
      }
      if(tx!=HostProbe.INSTALL&&tx!=HostProbe.FORWARD)
        return super.onTransact(tx,data,reply,flags);
      int answer=HostProbe.MALFORMED;
      try{
        data.enforceInterface(HostProbe.SLOT_DESCRIPTOR);
        if(tx==HostProbe.INSTALL){
          IBinder gate=data.readStrongBinder(),cap=data.readStrongBinder();
          int claim=data.readInt();
          if(claim==slotId()&&gate!=null&&cap!=null&&data.dataAvail()==0){
            hostGate=gate;capability=cap;answer=0;
          }
        } else if(hostGate!=null&&capability!=null){
          int requestType=data.readInt();
          int claim=data.readInt();
          long epoch=data.readLong(),seq=data.readLong();
          int op=data.readInt();
          if((requestType==HostProbe.REQUEST||requestType==HostProbe.RESULT)
              &&data.dataAvail()<=2048){
            byte[] payload=data.createByteArray();
            if(payload!=null&&data.dataAvail()==0){
              Parcel d=Parcel.obtain(),r=Parcel.obtain();
              try{
                d.writeInterfaceToken(HostProbe.HOST_DESCRIPTOR);
                d.writeStrongBinder(capability);
                d.writeInt(claim);
                d.writeLong(epoch);
                d.writeLong(seq);
                d.writeInt(op);
                d.writeByteArray(payload);
                if(hostGate.transact(requestType,d,r,0)){
                  r.readException();answer=r.readInt();
                }
              }finally{d.recycle();r.recycle();}
            }
          }
        }
      }catch(RuntimeException invalid){answer=HostProbe.MALFORMED;}
      reply.writeNoException();reply.writeInt(answer);return true;
    }
  };
  @Override public IBinder onBind(Intent intent){return entry;}
  public static final class A extends SlotService {
    @Override protected int slotId(){return 0;}
  }
  public static final class B extends SlotService {
    @Override protected int slotId(){return 1;}
  }
}
