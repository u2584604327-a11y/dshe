package com.dsh.android.p209;

import android.os.Process;
import android.util.Log;

/** Test-only witness immediately before the original start$2 PC3912 P40 call.
 * No new process, no permissions, no user information.
 */
public final class P209PreCallWitness {
  private static final String TAG="P209_PREP40";
  private P209PreCallWitness(){}
  /** Bounded CI-only original PC38 state-guard approach witness. */
  /** Test-only observation immediately after original PC26 if-eqz fallthrough. */
  /** Disposable marker after the original PC176 throwOnFailure normal return. */
  public static void markPostThrowOnFailure() {
    try {
      if (Process.isIsolated()) {
        Log.i("P209_TAKEN","P209_PC176_POSTCALL_ISOLATED=DENY");
        return;
      }
      Log.i("P209_TAKEN","P209_PC176_POST_THROWONFAILURE=OBSERVED");
    }catch(Throwable ignored) {
      // No logging side effect may modify original coroutine control flow.
    }
  }
  public static void markFallthrough() {
    try {
      if (Process.isIsolated()) {
        Log.i("P209_FALL","P209_PC30_FALL_ISOLATED=DENY");
        return;
      }
      Log.i("P209_FALL","P209_PC30_FALLTHROUGH=OBSERVED");
    }catch(Throwable ignored) {
      // Diagnostic failure cannot alter original app logic.
    }
  }
  public static void markFirstGuard() {
    try {
      if (Process.isIsolated()) {
        Log.i("P209_GUARD","P209_FIRST_GUARD_ISOLATED=DENY");
        return;
      }
      Log.i("P209_GUARD","P209_FIRST_GUARD=OBSERVED");
    }catch(Throwable ignored) {
      // No diagnostic may change original coroutine execution.
    }
  }
  public static void mark() {
    try {
      if (Process.isIsolated()) {
        Log.i(TAG,"P209_PRE_P40_ISOLATED=DENY");
        return;
      }
      Log.i(TAG,"P209_PRE_P40_WITNESS=OBSERVED");
    }catch(Throwable ignored) {
      // Test log failure must never change the original engine control flow.
    }
  }
}
