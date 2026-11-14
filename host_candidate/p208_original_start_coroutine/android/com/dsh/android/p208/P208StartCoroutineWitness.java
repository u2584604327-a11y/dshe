package com.dsh.android.p208;

import android.os.Process;
import android.util.Log;

/**
 * Disposable, non-production, original EngineManager$start$2.invokeSuspend method-entry
 * witness. Not an original coroutine/Node/runtime/Android UID attestation.
 * Every emitted string is a fixed nonprivate test status.
 */
public final class P208StartCoroutineWitness {
  private static final String TAG="P208_ORIGINAL_ENTRY";
  private P208StartCoroutineWitness(){}

  public static void mark() {
    try {
      if(Process.isIsolated()) {
        Log.i(TAG,"P208_ORIGINAL_START2_INVOKESUSPEND_ISOLATED_PROCESS=DENY");
        return;
      }
      Log.i(TAG,"P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED");
      Log.i(TAG,"P208_ORIGINAL_START2_COROUTINE_UID="+Process.myUid());
      Log.i(TAG,"P208_ORIGINAL_PROCESS_OWNER_EPOCH=NOT_ATTESTED");
      Log.i(TAG,"P208_ORIGINAL_NODE_HTTP_READY=NOT_WIRED");
    } catch(Throwable ignored) {
      // Test-only logging cannot be allowed to crash original bootEngine.
      // Inability to log is NOT a passing measurement.
    }
  }
}
