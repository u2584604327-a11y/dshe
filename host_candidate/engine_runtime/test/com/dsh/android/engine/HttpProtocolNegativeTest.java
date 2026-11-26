package com.dsh.android.engine;
import java.io.*;import java.net.*;import java.nio.*;import java.nio.charset.StandardCharsets;
import java.nio.file.*;import java.security.*;import java.util.*;import java.util.concurrent.*;
import javax.crypto.Mac;import javax.crypto.spec.SecretKeySpec;
public final class HttpProtocolNegativeTest {
 static int checks;static void yes(boolean b,String n){checks++;if(!b)throw new AssertionError(n);}
 static byte[] zeros=new byte[32];
 static Process start(ProcessBuilder builder)throws IOException{builder.environment().clear();return builder.start();}
 /** Models the supervisor's real rule: EXIT is published only after both
  * actual OS exit and release of this producer's stdin. No exit is invented. */
 static final class DrainedExit extends Process {
  final Process actual;final CountDownLatch producerClosed=new CountDownLatch(1);final OutputStream producer;
  DrainedExit(Process actual){this.actual=actual;producer=new FilterOutputStream(actual.getOutputStream()){
   @Override public void close()throws IOException{try{super.close();}finally{producerClosed.countDown();}}
  };}
  public InputStream getInputStream(){return actual.getInputStream();}
  public InputStream getErrorStream(){return actual.getErrorStream();}
  public OutputStream getOutputStream(){return producer;}
  public int waitFor()throws InterruptedException{int code=actual.waitFor();producerClosed.await();return code;}
  public boolean waitFor(long time,TimeUnit unit)throws InterruptedException{
   long start=System.nanoTime(),limit=unit.toNanos(time);if(!actual.waitFor(time,unit))return false;
   return producerClosed.await(Math.max(0,limit-(System.nanoTime()-start)),TimeUnit.NANOSECONDS);
  }
  public int exitValue(){if(producerClosed.getCount()!=0)throw new IllegalThreadStateException();return actual.exitValue();}
  public boolean isAlive(){return actual.isAlive()||producerClosed.getCount()!=0;}
  public void destroy(){actual.destroy();}
  public Process destroyForcibly(){actual.destroyForcibly();return this;}
 }
 static void unframedExit(String node,String peer)throws Exception{
  DrainedExit child=new DrainedExit(start(new ProcessBuilder(node,"--permission","--allow-fs-read="+peer,peer,"EOF_EXIT")));
  HttpProcessTransport transport=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
  try{
   yes(child.waitFor(5,TimeUnit.SECONDS),"eof_releases_exact_stdin_before_supervisor_exit");
   yes(child.exitValue()==7,"eof_still_requires_actual_child_exit_code");
   yes(transport.failure().equals("NONE/NONE"),"clean_unframed_exit_not_false_supervisor_failure_"+transport.failure());
  }finally{transport.close();}
 }
 static void hostRejects(String node,String peer,String mode,String expected)throws Exception{
  Process child=start(new ProcessBuilder(node,"--permission","--allow-fs-read="+peer,peer,mode));
  HttpProcessTransport transport=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
  int port=transport.port();Socket held=null;
  try{
   if(mode.equals("RESERVED_CREDIT")){yes(transport.awaitListening(3,TimeUnit.SECONDS),"listener_for_credit");held=new Socket("127.0.0.1",port);}
   yes(child.waitFor(5,TimeUnit.SECONDS),"bad_peer_revoked_"+mode);
   yes(transport.failure().startsWith(expected),"bad_peer_reason_"+mode+"="+transport.failure());
   try(Socket ignored=new Socket("127.0.0.1",port)){throw new AssertionError("revoked_port");}catch(ConnectException correct){checks++;}
  }finally{if(held!=null)held.close();transport.close();}
 }
 static byte[] frame(int type,int seq,int id,byte[] data,int declared,String mode)throws Exception{
  byte[] header=ByteBuffer.allocate(21).putInt(0x44484631).put((byte)type).putLong(seq).putInt(id).putInt(declared).array();
  Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(zeros,"HmacSHA256"));
  mac.update((byte)(mode.equals("REFLECT")?'N':'H'));mac.update(zeros);mac.update(ByteBuffer.allocate(8).putLong(mode.equals("OLD_EPOCH")?2:1).array());mac.update(header);
  byte[] signature=mac.doFinal(data);if(mode.equals("BAD_MAC"))signature[0]^=1;
  return ByteBuffer.allocate(53+data.length).put(header).put(signature).put(data).array();
 }
 static void nodeRejects(String node,String fixture,String source,String mode,String expected)throws Exception{
  Process child=start(new ProcessBuilder(node,"--permission","--allow-fs-read="+fixture,"--allow-fs-read="+source,fixture,source));
  try{
   DataOutputStream out=new DataOutputStream(child.getOutputStream());out.writeBytes("DSHHTTP1");out.write(zeros);out.write(zeros);out.writeLong(1);out.writeInt(0);out.writeInt(10000);out.flush();
   DataInputStream in=new DataInputStream(child.getInputStream());byte[] head=new byte[53];in.readFully(head);yes(head[4]==16,"node_original_http_listen");in.readFully(new byte[4]);
   byte[] attack;
   if(mode.equals("OVERSIZE"))attack=frame(7,1,0,new byte[0],16385,mode);
   else if(mode.equals("REMOTE_BIND"))attack=frame(1,1,1,new byte[]{8,8,8,8,0,0,0,80},8,mode);
   else if(mode.equals("CREDIT"))attack=frame(8,1,0,new byte[]{0,0,0,1},4,mode);
   else attack=frame(7,1,0,new byte[0],0,mode);
   out.write(attack);if(mode.equals("REPLAY"))out.write(attack);out.flush();
   yes(child.waitFor(5,TimeUnit.SECONDS),"bad_host_node_exited_"+mode);
   yes(child.exitValue()==125,"bad_host_node_exit_"+mode);
   byte[] stderr=new byte[1024];int n=child.getErrorStream().read(stderr);
   String fixed=n<0?"":new String(stderr,0,n,StandardCharsets.US_ASCII);
   yes(fixed.contains("DSH_RUNTIME_TRANSPORT_DENY="+expected),"bad_host_reason_"+mode);
  }finally{child.destroyForcibly();child.waitFor();}
 }
 static void startupExit(String node,String fixture,String source)throws Exception{
  Process child=start(new ProcessBuilder(node,"--permission","--allow-fs-read="+fixture,"--allow-fs-read="+source,fixture,source,"early-exit"));
  HttpProcessTransport process=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
  try{
   yes(process.waitFor(5,TimeUnit.SECONDS),"startup_exit_deadline");yes(process.exitValue()==7,"startup_exit_code_preserved");
   ByteArrayOutputStream bytes=new ByteArrayOutputStream();byte[] b=new byte[1024];int n;
   while((n=process.getErrorStream().read(b))!=-1)bytes.write(b,0,n);
   yes(bytes.toString("US-ASCII").equals("ORIGINAL_STARTUP_EXIT_BEFORE_LISTEN\n"),"startup_stderr_preserved");
   yes(process.failure().equals("NONE/NONE"),"startup_exit_not_supervisor_failure");
  }finally{process.close();}
 }
 static void logReaderChange(String node,String peer)throws Exception{
  Process child=start(new ProcessBuilder(node,"--permission","--allow-fs-read="+peer,peer,"LOG_READER_CHANGE"));
  HttpProcessTransport process=new HttpProcessTransport(child,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",1,0);
  try{
   InputStream output=process.getInputStream();
   FutureTask<String> initial=new FutureTask<>(()->OriginalMainHttpChecks.line(output));
   Thread reader=new Thread(initial,"first-log-reader");reader.setDaemon(true);reader.start();
   yes("first log".equals(initial.get(4,TimeUnit.SECONDS)),"first_log_reader");
   reader.join(2000);yes(!reader.isAlive(),"first_log_reader_ended");
   process.getOutputStream().write(1);
   yes(process.waitFor(5,TimeUnit.SECONDS)&&process.exitValue()==0,"log_delivered_with_no_current_reader");
   yes("second log".equals(OriginalMainHttpChecks.line(output)),"next_thread_reads_preserved_log");
   yes(output.read()==-1&&process.failure().equals("NONE/NONE"),"log_handoff_preserves_eof_and_exit");
  }finally{process.close();}
 }
 public static void main(String[] a)throws Exception{
  if(a.length==3&&a[2].equals("LOG_READER_ONLY")){logReaderChange(a[0],a[1]);return;}
  unframedExit(a[0],a[1]);
  if(a.length==3&&a[2].equals("EXIT_DRAIN_ONLY"))return;
  logReaderChange(a[0],a[1]);
  hostRejects(a[0],a[1],"EOF_ALIVE","PREMATURE_EOF");
  startupExit(a[0],a[2],a[3]);
  for(String mode:new String[]{"BAD_MAC","OLD_SESSION","REPLAY","OVERSIZE","UNSOLICITED","DUP_LISTEN","CREDIT","RESERVED_CREDIT"})
   hostRejects(a[0],a[1],mode,mode.equals("BAD_MAC")||mode.equals("OLD_SESSION")?"FRAME_AUTH":
       mode.equals("REPLAY")||mode.equals("OVERSIZE")?"FRAME_SHAPE":mode.equals("UNSOLICITED")?"CONNECTION_ID":
       mode.equals("DUP_LISTEN")?"LISTEN_REPLAY":"CREDIT_OVERFLOW");
  for(String mode:new String[]{"BAD_MAC","OLD_EPOCH","REFLECT","REPLAY","OVERSIZE","REMOTE_BIND","CREDIT"})
   nodeRejects(a[0],a[2],a[3],mode,mode.equals("REMOTE_BIND")?"E_DSH_IPC_OPEN":mode.equals("CREDIT")?"E_DSH_IPC_CREDIT":
       mode.equals("REPLAY")||mode.equals("OVERSIZE")?"E_DSH_IPC_FRAME":"E_DSH_IPC_AUTH");
  System.out.println("HTTP_PROCESS_PROTOCOL_REPLAY_GENERATION_AUTH_AND_CREDIT_NEGATIVES=PASS checks="+checks);
 }
}
