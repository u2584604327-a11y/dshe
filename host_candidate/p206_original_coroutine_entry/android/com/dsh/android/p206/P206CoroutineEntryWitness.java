package com.dsh.android.p206;

import android.os.Process;
import android.util.Log;

/**
 * Disposable, non-production, original MainActivity$bootEngine$1.invokeSuspend method-entry
 * witness. Not an original coroutine/Node/runtime/Android UID attestation.
 * Every emitted string is a fixed nonprivate test status.
 */
public final class P206CoroutineEntryWitness {
  private static final String TAG="P206_ORIGINAL_ENTRY";
  private P206CoroutineEntryWitness(){}

  public static void mark() {
    try {
      if(Process.isIsolated()) {
        Log.i(TAG,"P206_ORIGINAL_INVOKESUSPEND_ISOLATED_PROCESS=DENY");
        return;
      }
      Log.i(TAG,"P206_ORIGINAL_INVOKESUSPEND_METHOD_ENTRY=OBSERVED");
      Log.i(TAG,"P206_ORIGINAL_ENGINE_START_ENTRY=NOT_ATTESTED");
      Log.i(TAG,"P206_ORIGINAL_NODE_HTTP_READY=NOT_WIRED");
    } catch(Throwable ignored) {
      // Test-only logging cannot be allowed to crash original bootEngine.
      // Inability to log is NOT a passing measurement.
    }
  }
}
