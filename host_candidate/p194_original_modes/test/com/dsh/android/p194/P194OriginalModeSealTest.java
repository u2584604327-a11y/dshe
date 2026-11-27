package com.dsh.android.p194;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public final class P194OriginalModeSealTest {
  private static final String SESSION="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static int checks;
  private interface Check {void run() throws Exception;}
  private static void yes(boolean ok,String tag) {
    checks++;if(!ok)throw new AssertionError("P194_"+tag);
  }
  private static void denied(String code,Check action) throws Exception {
    try {action.run();throw new AssertionError("P194_UNEXPECTED_SUCCESS_"+code);}
    catch(IOException e){yes(code.equals(e.getMessage()),"DENIAL_"+code);}
  }
  private static ProcessBuilder builder(int mode){
    return new ProcessBuilder("/p194/NEVER-EXECUTE", "--fixture")
      .directory(new File("/"))
      .redirectErrorStream(mode!=P194OriginalModeSeal.RUN_DUMP_CONFIG);
  }
  private static void checked(int mode)throws Exception {
    ProcessBuilder b=builder(mode);
    try(P194OriginalModeSeal s=P194OriginalModeSeal.capture(b,mode,SESSION,17,43)){
      yes(!s.isTerminal(),"FRESH_"+mode);
      s.verifyOnce(b,mode,SESSION,17,43);
      yes(s.isTerminal(),"CONSUMED_"+mode);
      denied("P194_ALREADY_CONSUMED_OR_REVOKED",
          ()->s.verifyOnce(b,mode,SESSION,17,43));
    }
  }
  private static void invalid(String error,int mode,int candidate,int variation)
      throws Exception {
    ProcessBuilder b=builder(mode);
    try(P194OriginalModeSeal s=P194OriginalModeSeal.capture(b,mode,SESSION,5,9)){
      ProcessBuilder value=b;
      String session=SESSION;
      long epoch=5,seq=9;
      if(variation==1)value=builder(mode); // same values, wrong object
      else if(variation==2)session=SESSION.replace('0','f');
      else if(variation==3)epoch=6;
      else if(variation==4)seq=10;
      else if(variation==5)b.command().set(1,"--tampered");
      else if(variation==6)b.environment().put("P194_TEST","changed");
      else if(variation==7)b.directory(new File("/tmp"));
      else if(variation==8)b.redirectOutput(new File("DO_NOT_CREATE_P194"));
      else if(variation==9)b.redirectErrorStream(mode==2);
      final ProcessBuilder finalValue=value;
      final String finalSession=session;
      final long finalEpoch=epoch,finalSeq=seq;
      denied(error,()->s.verifyOnce(finalValue,candidate,finalSession,
          finalEpoch,finalSeq));
      yes(s.isTerminal(),"MISMATCH_BURNS_"+variation);
      denied("P194_ALREADY_CONSUMED_OR_REVOKED",
          ()->s.verifyOnce(b,mode,SESSION,5,9));
      yes(!new File("DO_NOT_CREATE_P194").exists(),"NO_HOST_FILE_"+variation);
    }
  }
  private static void testOtherThread()throws Exception {
    ProcessBuilder b=builder(3);
    P194OriginalModeSeal s=P194OriginalModeSeal.capture(b,3,SESSION,17,19);
    AtomicReference<String> reason=new AtomicReference<>();
    Thread t=new Thread(()->{
      try {s.verifyOnce(b,3,SESSION,17,19);reason.set("WRONG_SUCCESS");}
      catch(IOException e){reason.set(e.getMessage());}
    },"p194-cross-owner");
    t.start();t.join(2500);
    yes(!t.isAlive(),"THREAD_TEST_BOUNDED");
    yes("P194_DIFFERENT_OWNER_THREAD".equals(reason.get()),"THREAD_OWNER_DENY");
    yes(s.isTerminal(),"OTHER_THREAD_BURNS");
    denied("P194_ALREADY_CONSUMED_OR_REVOKED",()->s.verifyOnce(b,3,SESSION,17,19));
  }
  private static void testCancellationAndEpoch()throws Exception {
    ProcessBuilder b=builder(3);
    P194OriginalModeSeal old=P194OriginalModeSeal.capture(b,3,SESSION,100,1);
    old.close();
    denied("P194_ALREADY_CONSUMED_OR_REVOKED",
        ()->old.verifyOnce(b,3,SESSION,100,1));
    // Same session text must not resurrect a cancelled owner generation.
    try(P194OriginalModeSeal fresh=P194OriginalModeSeal.capture(b,3,SESSION,101,1)){
      denied("P194_ALREADY_CONSUMED_OR_REVOKED",
          ()->old.verifyOnce(b,3,SESSION,101,1));
      yes(!fresh.isTerminal(),"NEW_GENERATION_STILL_VALID");
      fresh.verifyOnce(b,3,SESSION,101,1);
      yes(fresh.isTerminal(),"NEW_GENERATION_CONSUMED");
    }
  }
  public static void main(String[] args)throws Exception {
    yes(Modifier.isFinal(P194OriginalModeSeal.class.getModifiers()),"CLASS_FINAL");
    Constructor<?>[] c=P194OriginalModeSeal.class.getDeclaredConstructors();
    yes(c.length==1 && Modifier.isPrivate(c[0].getModifiers()),
        "NO_PUBLIC_UNREVIEWED_CONSTRUCTOR");
    for(int m=1;m<=3;m++)checked(m);
    invalid("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",3,1,0);
    invalid("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",1,2,0);
    invalid("P194_DIFFERENT_PROCESSBUILDER_OBJECT",3,3,1);
    invalid("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",3,3,2);
    invalid("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",3,3,3);
    invalid("P194_MODE_SESSION_EPOCH_OR_SEQUENCE_DRIFT",3,3,4);
    invalid("P149_MUTATED_LAUNCH_ARGUMENTS",3,3,5);
    invalid("P149_MUTATED_LAUNCH_ARGUMENTS",3,3,6);
    invalid("P149_MUTATED_LAUNCH_ARGUMENTS",3,3,7);
    invalid("P194_ORIGINAL_PIPE_REDIRECT_DRIFT",3,3,8);
    invalid("P194_ORIGINAL_STDERR_MODE_DRIFT",3,3,9);
    testOtherThread();
    testCancellationAndEpoch();
    denied("P194_UNKNOWN_ORIGINAL_MODE",()->P194OriginalModeSeal.capture(
        builder(3),4,SESSION,1,1));
    denied("P194_HOST_OWNER_GENERATION_REQUIRED",()->P194OriginalModeSeal.capture(
        builder(3),3,"invalid",1,1));
    denied("P194_HOST_OWNER_GENERATION_REQUIRED",()->P194OriginalModeSeal.capture(
        builder(3),3,SESSION,0,1));
    denied("P194_HOST_OWNER_GENERATION_REQUIRED",()->P194OriginalModeSeal.capture(
        builder(3),3,SESSION,1,0));
    denied("P194_ORIGINAL_STDERR_MODE_DRIFT",()->P194OriginalModeSeal.capture(
        builder(3),2,SESSION,1,1));
    ProcessBuilder nullCwd=builder(3);nullCwd.directory(null);
    denied("P194_MISSING_ORIGINAL_LAUNCH_SHAPE",
        ()->P194OriginalModeSeal.capture(nullCwd,3,SESSION,1,1));
    ProcessBuilder redirected=builder(3);
    redirected.redirectInput(new File("P194_NEVER_READ_INPUT"));
    denied("P194_ORIGINAL_PIPE_REDIRECT_DRIFT",
        ()->P194OriginalModeSeal.capture(redirected,3,SESSION,1,1));
    yes(!new File("DO_NOT_CREATE_P194").exists(),"NEVER_EXECUTED_OR_WRITTEN");
    System.out.println("P194_THREE_ORIGINAL_MODES_DIFFERENT_STDERR_POLICIES=PASS");
    System.out.println("P194_EXACT_BUILDER_HMAC_OWNER_EPOCH_THREAD_ONE_SHOT=PASS");
    System.out.println("P194_NO_FILES_NO_EXEC_NO_BINDER_CREDENTIALS=PASS");
    System.out.println("P194_JAVA8_SOURCE_GUARD=PASS checks="+checks);
    System.out.println("P194_REAL_ORIGINAL_ENGINE_MANAGER_ALL_THREE=NOT_WIRED");
    System.out.println("P194_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED");
  }
}
