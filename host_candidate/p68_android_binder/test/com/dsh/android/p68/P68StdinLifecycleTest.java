package com.dsh.android.p68;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.TimeUnit;
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
  public static void main(String[] args)throws Exception{
    if(args.length==2&&args[0].startsWith("--")){
      if(args[0].equals("--closed")){
        System.in.close();System.out.println("CHILD_STDIN_CLOSED");System.out.flush();
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(12);
        while(!Files.exists(Paths.get(args[1]))&&System.nanoTime()<deadline)Thread.sleep(10);
        if(!Files.exists(Paths.get(args[1])))System.exit(99);
      }else if(args[0].equals("--eof")){
        if(!text(System.in).equals("abc"))System.exit(98);
      }else System.exit(97);
      System.err.print("LATE_CHILD_ERROR\n");System.err.flush();System.exit(7);
    }
    Path directory=Files.createTempDirectory("p68-stdin-lifecycle-");
    Path release=directory.resolve("release");
    try{
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
