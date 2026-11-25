package com.dsh.android.p68;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import java.io.*;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Actual Android Parcel/PFD status-channel regression; not a Binder UID or Node proof. */
public final class P68ReliablePipeLifecycleTest {
  private static final byte[] DATA=new byte[257];
  private static int checks;
  private static void check(boolean value,String reason){
    checks++;if(!value)throw new AssertionError(reason);
  }
  private static ParcelFileDescriptor copy(ParcelFileDescriptor source){
    Parcel parcel=Parcel.obtain();
    try{
      source.writeToParcel(parcel,0);parcel.setDataPosition(0);
      return ParcelFileDescriptor.CREATOR.createFromParcel(parcel);
    }finally{parcel.recycle();}
  }
  private static void close(ParcelFileDescriptor fd){
    if(fd!=null)try{fd.close();}catch(IOException ignored){}
  }
  private static int stdin(boolean oldOrdinaryClose)throws Exception{
    ParcelFileDescriptor[] pair=ParcelFileDescriptor.createReliablePipe();
    ParcelFileDescriptor receiver=copy(pair[0]);
    try{
      if(oldOrdinaryClose)pair[0].close();
      else P68AndroidBinderIntake.releaseTransferredCopy(pair[0]);
      try(OutputStream sender=new ParcelFileDescriptor.AutoCloseOutputStream(pair[1])){
        sender.write(DATA);
      }
      ByteArrayOutputStream childInput=new ByteArrayOutputStream();
      AtomicInteger sourceFailures=new AtomicInteger();
      Thread forward=P68AndroidBinderIntake.forwardStdin(
          new ParcelFileDescriptor.AutoCloseInputStream(receiver),childInput,
          sourceFailures::incrementAndGet);
      forward.join(3000);
      check(!forward.isAlive(),"stdin forwarding must terminate at EOF");
      check(Arrays.equals(DATA,childInput.toByteArray()),"full payload reaches child before EOF status check");
      return sourceFailures.get();
    }finally{close(receiver);close(pair[0]);close(pair[1]);}
  }
  private static boolean writerError(boolean oldOrdinaryClose)throws Exception{
    ParcelFileDescriptor[] pair=ParcelFileDescriptor.createReliablePipe();
    ParcelFileDescriptor writer=copy(pair[1]);
    try{
      if(oldOrdinaryClose)pair[1].close();
      else P68AndroidBinderIntake.releaseTransferredCopy(pair[1]);
      writer.closeWithError("P68_FIXED_NEGATIVE");
      try(InputStream receiver=new ParcelFileDescriptor.AutoCloseInputStream(pair[0])){
        try{receiver.read();return false;}
        catch(IOException expected){
          check("Remote error: P68_FIXED_NEGATIVE".equals(expected.getMessage()),"actual writer error must survive ownership transfer");
          return true;
        }
      }
    }finally{close(writer);close(pair[0]);close(pair[1]);}
  }
  private static void silentPeerLoss()throws Exception{
    ParcelFileDescriptor[] pair=ParcelFileDescriptor.createReliablePipe();
    try{
      // No live duplicate remains: dropping the writer without a status must
      // still report DEAD, unlike a completed ownership transfer to a peer.
      P68AndroidBinderIntake.releaseTransferredCopy(pair[1]);
      try(InputStream receiver=new ParcelFileDescriptor.AutoCloseInputStream(pair[0])){
        boolean denied=false;
        try{receiver.read();}
        catch(IOException expected){denied="Remote side is dead".equals(expected.getMessage());}
        check(denied,"silent peer loss must not become clean EOF");
      }
    }finally{close(pair[0]);close(pair[1]);}
  }
  private static void interactiveBufferedStdin()throws Exception{
    ParcelFileDescriptor[] upstream=ParcelFileDescriptor.createReliablePipe();
    ParcelFileDescriptor[] downstream=ParcelFileDescriptor.createReliablePipe();
    OutputStream producer=new ParcelFileDescriptor.AutoCloseOutputStream(upstream[1]);
    InputStream consumer=new ParcelFileDescriptor.AutoCloseInputStream(downstream[0]);
    CountDownLatch hello=new CountDownLatch(1),control=new CountDownLatch(1);
    AtomicInteger failures=new AtomicInteger();AtomicReference<Throwable> bad=new AtomicReference<>();
    Thread pump=null,reader=null;
    try{
      pump=P68AndroidBinderIntake.forwardStdin(new ParcelFileDescriptor.AutoCloseInputStream(upstream[0]),
          new BufferedOutputStream(new ParcelFileDescriptor.AutoCloseOutputStream(downstream[1]),8192),failures::incrementAndGet);
      reader=new Thread(()->{
        try{DataInputStream input=new DataInputStream(consumer);byte[] first=new byte[88],second=new byte[53];
          input.readFully(first);if(!Arrays.equals(first,Arrays.copyOfRange(DATA,0,88)))throw new IOException("P68_HELLO_BYTES");hello.countDown();
          input.readFully(second);if(!Arrays.equals(second,Arrays.copyOfRange(DATA,88,141)))throw new IOException("P68_FRAME_BYTES");control.countDown();
          if(input.read()!=-1)throw new IOException("P68_EOF_REQUIRED");
        }catch(Throwable error){bad.set(error);}
      },"p68-native-small-stdin");reader.setDaemon(true);reader.start();
      producer.write(DATA,0,88);producer.flush();
      check(hello.await(3,TimeUnit.SECONDS),"buffered native destination receives preface before upstream EOF");
      producer.write(DATA,88,53);producer.flush();
      check(control.await(3,TimeUnit.SECONDS),"subsequent short control frame arrives before EOF");
      check(pump.isAlive(),"interactive pipe stays open after control response");
      producer.close();pump.join(3000);reader.join(3000);
      check(!pump.isAlive()&&!reader.isAlive()&&failures.get()==0&&bad.get()==null,"interactive native EOF closes cleanly with exact bytes");
      System.out.println("P68_ANDROID35_BUFFERED_STDIN_PREFACE_AND_FRAME_BEFORE_EOF=PASS");
    }finally{
      try{producer.close();}catch(IOException ignored){}try{consumer.close();}catch(IOException ignored){}
      for(ParcelFileDescriptor fd:upstream)close(fd);for(ParcelFileDescriptor fd:downstream)close(fd);
    }
  }
  public static void main(String[] args)throws Exception{
    check(android.os.Process.myUid()==2000,"CI harness must run as shell UID, not root");
    for(int i=0;i<DATA.length;i++)DATA[i]=(byte)(i*31);
    check(stdin(true)==1,"original premature close must reproduce false transport loss after all bytes");
    System.out.println("P68_OLD_COMPLETE_STREAM_EOF_FALSE_CANCEL=REPRODUCED");
    check(stdin(false)==0,"ownership transfer must preserve clean stdin EOF");
    System.out.println("P68_RELIABLE_STDIN_EOF_NO_FALSE_CANCEL=PASS");
    check(!writerError(true),"original ordinary writer-copy close masks the true error");
    System.out.println("P68_OLD_WRITER_COPY_MASKED_ERROR=REPRODUCED");
    check(writerError(false),"real writer error must remain rejected");
    silentPeerLoss();
    System.out.println("P68_RELIABLE_WRITER_ERROR_AND_PEER_LOSS_STILL_DENIED=PASS");
    interactiveBufferedStdin();
    System.out.println("P68_ANDROID35_RELIABLE_PIPE_OWNERSHIP=PASS checks="+checks);
    System.out.println("P68_FIXTURE_BINDER_IDENTITY_AND_ARM64_NODE=NOT_ATTESTED");
  }
}
