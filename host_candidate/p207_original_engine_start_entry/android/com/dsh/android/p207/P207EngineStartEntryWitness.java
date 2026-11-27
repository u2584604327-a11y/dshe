package com.dsh.android.p207;

import android.os.Process;
import android.util.Log;

/**
 * Disposable, non-production, original EngineManager.start method-entry
 * witness. Not an original coroutine/Node/runtime/Android UID attestation.
 * Every emitted string is a fixed nonprivate test status.
 */
public final class P207EngineStartEntryWitness {
  private static final String TAG="P207_ORIGINAL_ENTRY";
  private P207EngineStartEntryWitness(){}

  public static void mark() {
    try {
      if(Process.isIsolated()) {
        Log.i(TAG,"P207_ORIGINAL_ENGINE_START_ISOLATED_PROCESS=DENY");
        return;
      }
      Log.i(TAG,"P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED");
      Log.i(TAG,"P207_ORIGINAL_ENGINE_START_RETURN=NOT_ATTESTED");
      Log.i(TAG,"P207_ORIGINAL_NODE_HTTP_READY=NOT_WIRED");
    } catch(Throwable ignored) {
      // Test-only logging cannot be allowed to crash original bootEngine.
      // Inability to log is NOT a passing measurement.
    }
  }
}
