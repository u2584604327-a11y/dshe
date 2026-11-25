package com.dsh.android.p68;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Real JVM child lifecycle, not a Node/Android/Binder attestation. */
public final class P68StdinLifecycleTest {
  private static int checks;
  private static void check(boolean condition,String message){
    checks++;if(!condition)throw new AssertionError(message);
  }
  private static String text(InputStream input)throws IOException{
    ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[256];int n;
    while((n=input.read(b))!=-1){
      if(n>4096-out.size())throw new IOException("TEST_CHILD_OUTPUT_BOUND");
      out.write(b,0,n);
    }
    return new String(out.toByteArray(),StandardCharsets.UTF_8);
  }
  private static Process child(String mode,Path release)throws IOException{
    ProcessBuilder launch=new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",
        System.getProperty("java.class.path"),P68StdinLifecycleTest.class.getName(),
        mode,release.toString());
    launch.environment().clear();return launch.start();
  }
  private static void awaitClosed(Process child)throws IOException{
    String line=new BufferedReader(new InputStreamReader(child.getInputStream(),StandardCharsets.UTF_8)).readLine();
    check("CHILD_STDIN_CLOSED".equals(line),"real child closed fd0 before forwarding");
  }
  private static byte[] packet(int length,int seed){
    byte[] result=new byte[length];for(int i=0;i<length;i++)result[i]=(byte)(seed+i*7);return result;
  }
  private static void bufferedDuplex(Path release,boolean legacy)throws Exception{
    Process process=child("--duplex",release);
    ExecutorService reads=Executors.newSingleThreadExecutor();
    PipedInputStream source=new PipedInputStream(8192);
    PipedOutputStream sender=new PipedOutputStream(source);
    CountDownLatch accepted=new CountDownLatch(1);AtomicInteger sourceFailures=new AtomicInteger();
    class Buffer extends BufferedOutputStream {
      Buffer(OutputStream target){super(target,8192);}
      @Override public synchronized void write(byte[] b,int o,int n)throws IOException{super.write(b,o,n);accepted.countDown();}
      synchronized int pending(){return count;}
    }
    Buffer destination=new Buffer(process.getOutputStream());Thread pump=null;
    try{
      BufferedReader stdout=new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.US_ASCII));
      check("PIPE_READY".equals(reads.submit(stdout::readLine).get(3,TimeUnit.SECONDS)),"real child is waiting for interactive stdin");
      pump=P68AndroidBinderIntake.forwardStdin(source,destination,sourceFailures::incrementAndGet);
      sender.write(packet(88,11));sender.flush();
      check(accepted.await(3,TimeUnit.SECONDS),"actual forwarding method accepted the complete short preface");
      Future<String> hello=reads.submit(stdout::readLine);
      if(legacy){
        check(destination.pending()==88,"original forwarder leaves the actual preface in its child buffer");
        try{hello.get(350,TimeUnit.MILLISECONDS);throw new AssertionError("legacy buffer unexpectedly delivered before EOF");}
        catch(TimeoutException expected){}
        check(process.isAlive()&&pump.isAlive(),"both sides remain live while the preface is buffered");
        sender.write(packet(53,29));sender.close();
        check("PIPE_HELLO_88".equals(hello.get(3,TimeUnit.SECONDS)),"original preface is delivered only after upstream EOF");
        check("PIPE_CONTROL_53".equals(reads.submit(stdout::readLine).get(3,TimeUnit.SECONDS)),"original control bytes finally delivered on close");
      }else{
        check("PIPE_HELLO_88".equals(hello.get(3,TimeUnit.SECONDS)),"preface reaches real child before producer EOF");
        check(destination.pending()==0&&pump.isAlive(),"short write flushed while input stays open");
        sender.write(packet(53,29));sender.flush();
        check("PIPE_CONTROL_53".equals(reads.submit(stdout::readLine).get(3,TimeUnit.SECONDS)),"subsequent small frame reaches child before EOF");
        check(pump.isAlive(),"interactive forwarding stays open after control response");sender.close();
      }
      pump.join(3000);check(!pump.isAlive()&&sourceFailures.get()==0,"clean EOF releases interactive pump without source failure");
      check(process.waitFor(3,TimeUnit.SECONDS)&&process.exitValue()==0,"actual duplex child exits normally after EOF");
      System.out.println(legacy?"P68_BUFFERED_CHILD_STDIN_HELLO_WITHHELD_UNTIL_EOF=REPRODUCED":
          "P68_BUFFERED_CHILD_STDIN_PREFACE_AND_FRAME_BEFORE_EOF=PASS");
    }finally{sender.close();source.close();process.destroyForcibly();reads.shutdownNow();if(pump!=null)pump.join(2000);}
  }
  public static void main(String[] args)throws Exception{
    if(args.length==2&&args[0].startsWith("--")){
      if(args[0].equals("--closed")){
        System.in.close();System.out.println("CHILD_STDIN_CLOSED");System.out.flush();
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(12);
        while(!Files.exists(Paths.get(args[1]))&&System.nanoTime()<deadline)Thread.sleep(10);
        if(!Files.exists(Paths.get(args[1])))System.exit(99);
      }else if(args[0].equals("--duplex")){
        System.out.println("PIPE_READY");System.out.flush();DataInputStream input=new DataInputStream(System.in);
        byte[] hello=new byte[88];input.readFully(hello);if(!Arrays.equals(hello,packet(88,11)))System.exit(96);
        System.out.println("PIPE_HELLO_88");System.out.flush();
        byte[] control=new byte[53];input.readFully(control);if(!Arrays.equals(control,packet(53,29)))System.exit(95);
        System.out.println("PIPE_CONTROL_53");System.out.flush();if(input.read()!=-1)System.exit(94);System.exit(0);return;
      }else if(args[0].equals("--eof")){
        if(!text(System.in).equals("abc"))System.exit(98);
      }else System.exit(97);
      System.err.print("LATE_CHILD_ERROR\n");System.err.flush();System.exit(7);
    }
    Path directory=Files.createTempDirectory("p68-stdin-lifecycle-");
    Path release=directory.resolve("release");
    try{
      boolean legacy=args.length==1&&args[0].equals("--legacy-buffered");
      bufferedDuplex(release,legacy);if(legacy)return;
      Process process=child("--closed",release);
      try{
        awaitClosed(process);
        AtomicInteger sourceFailures=new AtomicInteger(),sourceClosed=new AtomicInteger();
        InputStream source=new ByteArrayInputStream(new byte[2*1024*1024]){
          public void close(){sourceClosed.incrementAndGet();}
        };
        Thread pump=P68AndroidBinderIntake.forwardStdin(source,process.getOutputStream(),()->{
          sourceFailures.incrementAndGet();process.destroyForcibly();
        });
        pump.join(3000);
        check(!pump.isAlive(),"closed child input releases the source pump");
        check(sourceClosed.get()==1,"upstream endpoint closed once");
        check(sourceFailures.get()==0,"child input closure is not transport loss");
        check(process.isAlive(),"child must remain alive to print its actual error");
        Files.write(release,new byte[]{1});
        check(process.waitFor(3,TimeUnit.SECONDS)&&process.exitValue()==7,"actual nonzero child exit preserved");
        check(text(process.getErrorStream()).equals("LATE_CHILD_ERROR\n"),"late stderr preserved after stdin closure");
      }finally{process.destroyForcibly();}
      Files.deleteIfExists(release);

      Process lost=child("--closed",release);
      try{
        awaitClosed(lost);
        AtomicInteger failures=new AtomicInteger(),closed=new AtomicInteger();
        InputStream source=new InputStream(){
          public int read()throws IOException{throw new IOException("AUTHENTICATED_TRANSPORT_LOST");}
          public void close(){closed.incrementAndGet();}
        };
        Thread pump=P68AndroidBinderIntake.forwardStdin(source,lost.getOutputStream(),()->{
          failures.incrementAndGet();lost.destroyForcibly();
        });
        pump.join(3000);
        check(!pump.isAlive()&&failures.get()==1,"real source failure invokes cancellation exactly once");
        check(closed.get()==1,"failed transport endpoint released");
        check(lost.waitFor(3,TimeUnit.SECONDS)&&lost.exitValue()!=7,"transport loss still kills the real child");
      }finally{lost.destroyForcibly();}

      Process eof=child("--eof",release);
      try{
        AtomicInteger failures=new AtomicInteger();
        Thread pump=P68AndroidBinderIntake.forwardStdin(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)),
            eof.getOutputStream(),failures::incrementAndGet);
        pump.join(3000);
        check(!pump.isAlive()&&failures.get()==0,"normal stdin EOF forwarded without cancellation");
        check(eof.waitFor(3,TimeUnit.SECONDS)&&eof.exitValue()==7,"EOF child actual exit preserved");
        check(text(eof.getErrorStream()).equals("LATE_CHILD_ERROR\n"),"EOF child stderr tail preserved");
      }finally{eof.destroyForcibly();}
      System.out.println("P68_REAL_CHILD_STDIN_CLOSE_PRESERVES_STDERR_AND_EXIT=PASS checks="+checks);
      System.out.println("P68_REAL_STDIN_TRANSPORT_LOSS_STILL_CANCELS=PASS");
      System.out.println("P68_ANDROID_ARM64_NODE_RUNTIME=NOT_ATTESTED");
    }finally{Files.deleteIfExists(release);Files.delete(directory);}
  }
}
