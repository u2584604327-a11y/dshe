package com.dsh.android.p150;
import java.util.Arrays;
public final class P150OriginTest{
  static void must(boolean v){if(!v)throw new AssertionError("P150_ORIGIN_ASSERT");}
  static StackTraceElement f(String c,String m){return new StackTraceElement(c,m,"Fixture.java",1);}
  static StackTraceElement[] sample(){
    return new StackTraceElement[]{f("java.lang.Thread","getStackTrace"),
      f("com.dsh.android.p150.P150OriginalCoroutineObserver","recordFromP47"),
      f("com.dsh.android.p47.P47LaunchGate","startOrDeny"),
      f("com.dsh.android.p40.P40ProcessBridge","start"),
      f("com.dsh.android.EngineManager$start$2","invokeSuspend")};
  }
  public static void main(String[] args){
    must(P150OriginalCoroutineObserver.isOriginalStack(sample()));
    StackTraceElement[] wrong=sample();wrong[4]=f("com.dsh.android.p43.P43ProbeActivity","assertExactBridgeFailClosed");
    must(!P150OriginalCoroutineObserver.isOriginalStack(wrong));
    wrong=sample();wrong[4]=f("com.dsh.android.EngineManager$start$2","notInvokeSuspend");
    must(!P150OriginalCoroutineObserver.isOriginalStack(wrong));
    wrong=sample();wrong[3]=f("com.dsh.android.p40.P40ProcessBridge","startAgain");
    must(!P150OriginalCoroutineObserver.isOriginalStack(wrong));
    wrong=Arrays.copyOf(sample(),6);wrong[5]=wrong[4];
    must(!P150OriginalCoroutineObserver.isOriginalStack(wrong));
    must(!P150OriginalCoroutineObserver.isOriginalStack(null));
    int n=P150OriginalCoroutineObserver.observedOther();
    P150OriginalCoroutineObserver.recordFromP47();
    must(P150OriginalCoroutineObserver.observedOther()==n+1);
    must(P150OriginalCoroutineObserver.observedOriginal()==0);
    System.out.println("P150_SYNTHETIC_STACK_CLASSIFIER_NEGATIVES=PASS");
    System.out.println("P150_TEST_CLASSIFIER_IS_NOT_RUNTIME_ORIGIN_PROOF=YES");
  }
}
