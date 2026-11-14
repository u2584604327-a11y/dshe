package com.dsh.android.p141;

import com.dsh.p37.P37RemoteProcess;
import com.dsh.android.p53.P53StartOrder;
import com.dsh.android.p67.P67AuthenticatedHandoff;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

/** P141 pure JVM, exact P53 authenticated delivery order and Process semantics. */
public final class P141RedirectedEngineStreamTest {
  private static final int UID=99055;
  private static final String SESSION="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  private static int tests;
  private static void ok(boolean value,String name){
    tests++; if(!value)throw new AssertionError("P141_"+name);
  }
  private static class Stops implements P37RemoteProcess.RemoteControl{
    int soft,hard;
    public void requestGracefulStop(){soft++;}
    public void requestForceStop(){hard++;}
  }
  private static P67AuthenticatedHandoff newHost(Stops stops,boolean merge){
    return new P67AuthenticatedHandoff(
      UID,SESSION,uid->uid==UID,stops,merge);
  }
  private static boolean send(P67AuthenticatedHandoff p,int kind,long sequence,String payload){
    return p.onAuthenticatedFrame(UID,SESSION,kind,sequence,
      payload==null?null:payload.getBytes(StandardCharsets.UTF_8),0);
  }
  private static byte[] readAll(InputStream in)throws IOException{
    ByteArrayOutputStream out=new ByteArrayOutputStream();
    byte[] b=new byte[128];int n;
    while((n=in.read(b))!=-1)out.write(b,0,n);
    return out.toByteArray();
  }
  private static void testMergedAfterRealChildAck()throws Exception{
    Stops ctrl=new Stops();
    P67AuthenticatedHandoff p=newHost(ctrl,true);
    ok(p.processAfterVerifiedChildStart()==null,"NO_PROCESS_FROM_CONSTRUCTOR");
    ok(send(p,P53StartOrder.HELLO,0,null),"HELLO");
    ok(!p.hasVerifiedOriginalEngineReady(),"HELLO_NOT_READY");
    ok(p.processAfterVerifiedChildStart()==null,"HELLO_NOT_PROCESS");
    ok(send(p,P53StartOrder.CHILD_STARTED,1,null),"CHILD_STARTED");
    Process out=p.processAfterVerifiedChildStart();
    ok(out!=null,"PROCESS_HANDOFF");
    ok(!p.hasVerifiedOriginalEngineReady(),"CHILD_NOT_READY");
    ok(out.getErrorStream().read()==-1,"REDIRECTED_STDERR_IS_EOF");
    ok(send(p,P53StartOrder.STDOUT,2,"boot\n"),"FIRST_STDOUT");
    ok(send(p,P53StartOrder.STDERR,3,"diagnostic\n"),"MERGED_STDERR");
    ok(send(p,P53StartOrder.STDOUT,4,"dsh web: http://127.0.0.1:1604/?token=placeholder\n"),"FOLLOWING_STDOUT");
    ok(!p.hasVerifiedOriginalEngineReady(),"URL_TEXT_ALONE_NOT_READY");
    ok(send(p,P53StartOrder.EXIT,5,null),"EXIT");
    String all=new String(readAll(out.getInputStream()),StandardCharsets.UTF_8);
    ok(all.equals("boot\ndiagnostic\ndsh web: http://127.0.0.1:1604/?token=placeholder\n"),
       "EXACT_AUTHENTICATED_MERGED_FRAME_ORDER");
    ok(out.getErrorStream().read()==-1,"STDERR_EOF_AFTER_EXIT");
    ok(out.exitValue()==0&&out.waitFor(0,TimeUnit.MILLISECONDS),"PROCESS_TERMINAL");
    ok(!p.hasVerifiedOriginalEngineReady(),"EXIT_NOT_READY");
    ok(ctrl.hard==0&&ctrl.soft==0,"NO_UNREQUESTED_TERMINATION");
  }
  private static void testLegacySplitUnchanged()throws Exception{
    P67AuthenticatedHandoff p=newHost(new Stops(),false);
    ok(send(p,P53StartOrder.HELLO,0,null),"LEGACY_HELLO");
    ok(send(p,P53StartOrder.CHILD_STARTED,1,null),"LEGACY_START");
    Process proc=p.processAfterVerifiedChildStart();
    ok(send(p,P53StartOrder.STDERR,2,"legacy-error\n"),"LEGACY_STDERR");
    ok(send(p,P53StartOrder.STDOUT,3,"legacy-out\n"),"LEGACY_STDOUT");
    ok(send(p,P53StartOrder.EXIT,4,null),"LEGACY_EXIT");
    ok("legacy-out\n".equals(new String(readAll(proc.getInputStream()),StandardCharsets.UTF_8)),
       "LEGACY_STDOUT_UNCHANGED");
    ok("legacy-error\n".equals(new String(readAll(proc.getErrorStream()),StandardCharsets.UTF_8)),
       "LEGACY_STDERR_UNCHANGED");
  }
  private static void testSpoofAndOverflowRevoke()throws Exception{
    Stops stopped=new Stops();
    P67AuthenticatedHandoff p=newHost(stopped,true);
    ok(send(p,P53StartOrder.HELLO,0,null),"SPOOF_HELLO");
    ok(send(p,P53StartOrder.CHILD_STARTED,1,null),"SPOOF_CHILD");
    Process proc=p.processAfterVerifiedChildStart();
    ok(!p.onAuthenticatedFrame(UID+1,SESSION,P53StartOrder.STDERR,2,
        new byte[]{(byte)'x'},0),"FORGED_BINDER_UID_BLOCKED");
    ok(proc.waitFor(0,TimeUnit.MILLISECONDS)&&proc.exitValue()==125,"SPOOF_TERMINAL");
    ok(proc.getInputStream().read()==-1,"SPOOF_DISCARDS_PENDING_TOKENS");
    ok(stopped.hard==1,"SPOOF_FORCE_STOP_ONCE");

    Stops stops=new Stops();
    P67AuthenticatedHandoff bounded=newHost(stops,true);
    ok(send(bounded,P53StartOrder.HELLO,0,null),"BOUND_HELLO");
    ok(send(bounded,P53StartOrder.CHILD_STARTED,1,null),"BOUND_CHILD");
    Process remote=bounded.processAfterVerifiedChildStart();
    byte[] chunk=new byte[P37RemoteProcess.MAX_FRAME_BYTES];
    Arrays.fill(chunk,(byte)'a');
    for(int i=0;i<16;i++)
      ok(bounded.onAuthenticatedFrame(UID,SESSION,
        (i%2==0?P53StartOrder.STDERR:P53StartOrder.STDOUT),i+2,chunk,0),
        "BOUND_FRAME_"+i);
    ok(!bounded.onAuthenticatedFrame(UID,SESSION,P53StartOrder.STDERR,
       18,new byte[]{(byte)'b'},0),"MERGED_OVERFLOW_DENIED");
    ok(remote.exitValue()==125&&remote.getInputStream().read()==-1,
       "OVERFLOW_DISCARDS_MERGED_READY");
    ok(stops.hard==1,"OVERFLOW_KILL_ONCE");
    ok(!bounded.hasVerifiedOriginalEngineReady(),"OVERFLOW_NOT_READY");
  }
  public static void main(String[] args)throws Exception{
    testMergedAfterRealChildAck();testLegacySplitUnchanged();testSpoofAndOverflowRevoke();
    System.out.println("P141_P53_P67_P37_TRUSTED_REDIRECT_ERROR_STREAM_TESTS=PASS assertions="+tests);
    System.out.println("P141_MERGED_STREAM_ORDERED_BY_VERIFIED_BINDER_SEQUENCE=PASS");
    System.out.println("P141_LEGACY_P51_SPLIT_STDOUT_STDERR=PASS_UNCHANGED");
    System.out.println("P141_REAL_ENGINE_READY_AFTER_AUTH_CHILD=NOT_GRANTED");
    System.out.println("P141_PRODUCTION_ARGV_AND_FD_BROKER=NOT_WIRED");
    System.out.println("P141_NATIVE_SENSITIVE_TOOLS=DENY_ALL");
    System.out.println("P141_FORMAL_V139=BLOCKED");
  }
}
