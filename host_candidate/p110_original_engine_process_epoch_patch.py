#!/usr/bin/env python3
"""P110 pinned original EngineManager PROCESS identity epoch, diagnostics-only.

The P108 MainActivity epoch follows Activity observation, not a Node Process.
P110 tracks the actual Process object owned by original EngineManager.
Neither is proof of an original live SessionStore or pending ToolRuntime call.
Never approves tools, binds a worker, modifies the original Node, or signs an APK.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

ENGINE = "app/src/main/java/com/dsh/android/EngineManager.kt"
TRACKER = "app/src/main/java/com/dsh/android/p110/P110OriginalProcessEpoch.java"
JAVA = """// Unofficial bounded compatibility addition to pht88888888/DSHAPP (MIT).
package com.dsh.android.p110;

/** Original host Process object identity, NOT an original tool-call authorization.
 * Only original EngineManager may call onProcessStarted/onProcessStopped.
 * Never accept a PID, epoch, sessionId or callId supplied by Node/WebView/mailbox.
 */
public final class P110OriginalProcessEpoch {
  private long epoch;
  private Process owner;
  private boolean exhausted;

  public synchronized void onProcessStarted(Process originalProcess) {
    if (originalProcess == null || exhausted || owner == originalProcess) return;
    if (epoch == Long.MAX_VALUE) {
      exhausted = true;
      owner = null;
      return;
    }
    epoch++;
    owner = originalProcess;
  }

  public synchronized void onProcessStopped(Process originalProcess) {
    if (originalProcess != null && owner == originalProcess) owner = null;
  }

  public synchronized void onAllProcessesStopped() {
    owner = null;
  }

  /** Null is the only result for a dead, replaced, non-ready or revoked process. */
  public synchronized Long currentGeneration(Process current, boolean originalStateReady) {
    if (exhausted || !originalStateReady || current == null ||
        owner != current || !current.isAlive()) return null;
    return Long.valueOf(epoch);
  }
}
"""

PROBE = """import com.dsh.android.p110.P110OriginalProcessEpoch;
import java.io.*;
import java.util.Objects;
public final class P110Probe {
  static final class FakeProcess extends Process {
    boolean alive = true;
    public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
    public InputStream getInputStream() { return new ByteArrayInputStream(new byte[0]); }
    public InputStream getErrorStream() { return new ByteArrayInputStream(new byte[0]); }
    public int waitFor() { return 0; }
    public int exitValue() { return 0; }
    public void destroy() { alive = false; }
    public boolean isAlive() { return alive; }
  }
  static void eq(Long expected, Long actual) {
    if (!Objects.equals(expected, actual)) throw new AssertionError(
      "expected=" + expected + " actual=" + actual);
  }
  public static void main(String[] args) {
    P110OriginalProcessEpoch t = new P110OriginalProcessEpoch();
    FakeProcess p1 = new FakeProcess();
    FakeProcess p2 = new FakeProcess();
    FakeProcess p3 = new FakeProcess();
    eq(null, t.currentGeneration(p1, true));
    t.onProcessStarted(p1);
    eq(null, t.currentGeneration(p1, false));
    eq(1L, t.currentGeneration(p1, true));
    t.onProcessStarted(p1); // repeated Activity Ready must not mint a process
    eq(1L, t.currentGeneration(p1, true));
    t.onProcessStarted(p2);
    eq(null, t.currentGeneration(p1, true));
    eq(2L, t.currentGeneration(p2, true));
    t.onProcessStopped(p1); // late old stdout EOF cannot revoke new owner
    eq(2L, t.currentGeneration(p2, true));
    p2.destroy();
    eq(null, t.currentGeneration(p2, true));
    t.onProcessStopped(p2);
    eq(null, t.currentGeneration(p2, true));
    t.onProcessStarted(p3);
    eq(3L, t.currentGeneration(p3, true));
    t.onAllProcessesStopped();
    eq(null, t.currentGeneration(p3, true));
    System.out.println("P110_ACTUAL_COMPILED_JAVA_PROCESS_IDENTITY_PROBE=PASS");
    System.out.println("P110_ACTIVITY_EPOCH_NOT_PROCESS_GENERATION=CONFIRMED");
    System.out.println("P110_ORIGINAL_SESSIONSTORE_AND_TOOLRUNTIME_OWNER=NOT_WIRED");
  }
}
"""

def once(source, old, new):
    count = source.count(old)
    if count != 1:
        raise ValueError("P110_PINNED_ENGINE_ANCHOR_COUNT_" + str(count))
    return source.replace(old, new)

def apply(root):
    src = root / ENGINE
    dest = root / TRACKER
    if not src.is_file() or dest.exists():
        raise ValueError("P110_PINNED_ENGINE_SOURCE_REQUIRED")
    s = src.read_text(encoding="utf-8")
    s = once(s,
        "    @Volatile\n    private var process: Process? = null\n",
        "    @Volatile\n    private var process: Process? = null\n"
        "    // This is owned by the original EngineManager, not by MainActivity or Node.\n"
        "    private val p110OriginalProcessEpoch =\n"
        "        com.dsh.android.p110.P110OriginalProcessEpoch()\n\n"
        "    /** Diagnostics only; NEVER use this alone to authorize a tool call. */\n"
        "    fun originalProcessEpochForNativeDiagnostics(): Long? =\n"
        "        p110OriginalProcessEpoch.currentGeneration(\n"
        "            process, _state.value is State.Ready)\n")
    s = once(s,
        "        process = proc\n\n        // 只用一个后台线程",
        "        process = proc\n"
        "        // Only an actual ProcessBuilder.start() success mints this host epoch.\n"
        "        p110OriginalProcessEpoch.onProcessStarted(proc)\n\n"
        "        // 只用一个后台线程")
    s = once(s,
        "    fun stop() {\n        stopHeapWatch()",
        "    fun stop() {\n"
        "        // Revoke first; do not grant capabilities or interrupt other AgentLoop logic.\n"
        "        p110OriginalProcessEpoch.onAllProcessesStopped()\n"
        "        stopHeapWatch()")
    s = once(s,
        "        if (process !== proc) return\n        if (!wasReady) return",
        "        if (process !== proc) return\n"
        "        // Stale stdout EOF is rejected by tracker identity, never a PID claim.\n"
        "        p110OriginalProcessEpoch.onProcessStopped(proc)\n"
        "        if (!wasReady) return")
    src.write_text(s, encoding="utf-8")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(JAVA, encoding="utf-8")
    print("P110_REAL_ORIGINAL_ENGINEMANAGER_PROCESS_LIFECYCLE_PATCH=PASS")
    print("P110_ACTIVITY_OBSERVATION_EPOCH_NOT_USED_AS_PROCESS_OWNER=YES")
    print("P110_NATIVE_TOOL_APPROVAL_OR_BINDER=NONE")
    print("P110_ORIGINAL_SESSIONSTORE_TOOLRUNTIME_CALL_OWNERSHIP=NOT_WIRED")
    print("P110_SIGNED_APK=NONE")

def selftest(root):
    if not (root / TRACKER).is_file():
        raise ValueError("P110_JAVA_SOURCE_NOT_PATCHED")
    with tempfile.TemporaryDirectory() as d:
        probe = Path(d) / "P110Probe.java"
        probe.write_text(PROBE, encoding="utf-8")
        subprocess.run(["javac", "-encoding", "UTF-8", "-d", d,
            str(root / TRACKER), str(probe)], check=True)
        subprocess.run(["java", "-cp", d, "P110Probe"], check=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-dir", type=Path, required=True)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest(args.upstream_dir)
    else:
        apply(args.upstream_dir)
