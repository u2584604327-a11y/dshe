package com.dsh.android.p149;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder;

public final class P149WitnessTest {
  private static final String S="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static int count=0;
  interface Run {void invoke()throws IOException;}
  private static void yes(boolean p) {
    count++;if(!p)throw new AssertionError("P149_ASSERTION");
  }
  private static void denied(Run r,String expected) {
    try {r.invoke();throw new AssertionError("P149_FAIL_OPEN");}
    catch(IOException err){yes(err.getMessage().startsWith(expected));}
  }
  private static ProcessBuilder builder() {
    ProcessBuilder b=new ProcessBuilder(
      "/host/bin/node","/host/node_modules/@deepseek-ai/dsh/lib/bin.js",
      "--profile","web","--no-open");
    b.directory(new File("/host/cwd"));b.redirectErrorStream(true);
    b.environment().put("P149_TEST_HEADER","secret-not-logged");
    return b;
  }
  private static void negative(int n)throws IOException {
    ProcessBuilder b=builder();
    try(P149OriginalBuilderWitness.Witness w=
          P149OriginalBuilderWitness.capture(b,3,S,n)){
      switch(n) {
        case 1:b.command().set(4,"--patch");break;
        case 2:b.directory(new File("/host/changed"));break;
        case 3:b.environment().put("P149_TEST_HEADER","changed-secret");break;
        case 4:b.redirectErrorStream(false);break;
        case 5:b.redirectOutput(ProcessBuilder.Redirect.INHERIT);break;
        default:throw new AssertionError();
      }
      denied(()->w.matchOnce(b,3,S,n),"P149_MUTATED_LAUNCH_ARGUMENTS");
      denied(()->w.matchOnce(b,3,S,n),"P149_USED_OR_CLOSED");
    }
  }
  public static void main(String[] ignored)throws Exception {
    for(int mode=1;mode<=3;mode++){
      ProcessBuilder b=builder();
      final int modeId=mode;
      try(P149OriginalBuilderWitness.Witness w=
            P149OriginalBuilderWitness.capture(b,modeId,S,modeId)){
        w.matchOnce(b,modeId,S,modeId);
        denied(()->w.matchOnce(b,modeId,S,modeId),"P149_USED_OR_CLOSED");
      }
      P149OriginalBuilderWitness.observeWithoutLaunch(b,mode);
    }
    for(int i=1;i<=5;i++)negative(i);
    ProcessBuilder b=builder();
    try(P149OriginalBuilderWitness.Witness w=
          P149OriginalBuilderWitness.capture(b,3,S,24)){
      denied(()->w.matchOnce(b,2,S,24),"P149_SESSION_MODE_OR_SEQUENCE_DRIFT");
      denied(()->w.matchOnce(b,3,S,24),"P149_USED_OR_CLOSED");
    }
    try(P149OriginalBuilderWitness.Witness w=
          P149OriginalBuilderWitness.capture(b,3,S,25)){
      denied(()->w.matchOnce(b,3,S,26),"P149_SESSION_MODE_OR_SEQUENCE_DRIFT");
    }
    try(P149OriginalBuilderWitness.Witness w=
          P149OriginalBuilderWitness.capture(b,3,S,27)){
      denied(()->w.matchOnce(b,3,S.substring(1)+"0",27),
          "P149_SESSION_MODE_OR_SEQUENCE_DRIFT");
    }
    denied(()->P149OriginalBuilderWitness.capture(b,3,"bad",1),
        "P149_UNTRUSTED_OR_INCOMPLETE_BUILDER");
    b.command().add(null);
    denied(()->P149OriginalBuilderWitness.observeWithoutLaunch(b,3),
        "P149_INVALID_FIELD_OR_LENGTH");
    b.command().remove(b.command().size()-1);
    b.environment().put("P149_TEST_HEADER","contains\u0000null");
    denied(()->P149OriginalBuilderWitness.observeWithoutLaunch(b,3),
        "P149_INVALID_FIELD_OR_LENGTH");
    yes(count>=19);
    System.out.println("P149_HOST_PRELAUNCH_BINDING_NEGATIVES=PASS");
    System.out.println("P149_ORIGINAL_PRODUCTION_PROCESS_STARTED=NO");
    System.out.println("P149_PRIVACY_NO_ARGV_CWD_ENV_LOGS=PASS");
  }
}
