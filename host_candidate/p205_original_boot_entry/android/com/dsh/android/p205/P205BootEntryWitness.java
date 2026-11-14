package com.dsh.android.p205;

import android.os.Looper;
import android.os.Process;
import android.util.Log;

/**
 * Disposable CI-only original bootEngine method-entry diagnostic.
 * Caller names are classified to fixed enums, never logged verbatim.
 * Java stack traces are NOT Android OS Activity-instance or process attestation.
 * P47 remains DENY; never invokes the original engine, Node or browser.
 */
public final class P205BootEntryWitness {
  private static final String TAG="P205_ORIGINAL_ENTRY";
  private static int entryCount;
  private P205BootEntryWitness(){}

  private static String callerKind() {
    StackTraceElement[] stack=Thread.currentThread().getStackTrace();
    for(int i=0;i+1<stack.length;i++){
      StackTraceElement frame=stack[i];
      if(!"com.dsh.android.MainActivity".equals(frame.getClassName()) ||
         !"bootEngine".equals(frame.getMethodName()))continue;
      StackTraceElement caller=stack[i+1];
      String name=caller.getClassName();
      if("com.dsh.android.MainActivity".equals(name)) {
        return "onCreate".equals(caller.getMethodName())?"ONCREATE":"MAINACTIVITY_OTHER";
      }
      if(name.startsWith("com.dsh.android.MainActivity$"))return "MAINACTIVITY_NESTED";
      return "OTHER_OR_UNKNOWN";
    }
    return "UNAVAILABLE";
  }

  public static synchronized void mark() {
    try {
      if(Process.isIsolated()) {
        Log.i(TAG,"P205_ORIGINAL_BOOTENGINE_ISOLATED_PROCESS=DENY");
        return;
      }
      String occurrence=entryCount==0?"FIRST":entryCount==1?"SECOND":"LATER";
      if(entryCount<3)entryCount++;
      String caller=callerKind();
      String thread=Looper.myLooper()==Looper.getMainLooper()?"MAIN":"OTHER";
      Log.i(TAG,"P205_ORIGINAL_BOOTENGINE_"+occurrence+"_CALLER="+caller);
      Log.i(TAG,"P205_ORIGINAL_BOOTENGINE_"+occurrence+"_THREAD="+thread);
      Log.i(TAG,"P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED");
      Log.i(TAG,"P205_ORIGINAL_COROUTINE_INVOKESUSPEND=NOT_ATTESTED");
      Log.i(TAG,"P205_ORIGINAL_NODE_HTTP_READY=NOT_WIRED");
    } catch(Throwable ignored) {
      // CI diagnostic failure does not alter original bootEngine execution.
      // A missing status is never a passing observation.
    }
  }
}
