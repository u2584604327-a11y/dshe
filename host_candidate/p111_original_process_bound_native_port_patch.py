#!/usr/bin/env python3
"""P111 original EngineManager Process epoch -> P109 native-port revocation.
Applies ONLY after pinned MIT upstream + P108/P109/P110 patches.
No Binder service binding, node API, device action, APK or signature is added.
"""
import argparse
from pathlib import Path
import tempfile
import subprocess

ACTIVITY="app/src/main/java/com/dsh/android/MainActivity.kt"
BOUNDARY="app/src/main/java/com/dsh/android/P109OriginalToolHostBoundary.kt"
GATE="app/src/main/java/com/dsh/android/p111/P111NativeProcessSnapshot.java"

JAVA="""// Unofficial bounded adaptation to original pht88888888/DSHAPP MIT.
package com.dsh.android.p111;

/** Only host EngineManager's Process object may determine this generation.
 * Node/PID/IPC supplied generations NEVER authorize a tool call.
 * Lifecycle changes revoke existing native approval state.
 */
public final class P111NativeProcessSnapshot {
  private Long observed;
  private boolean destroyed;
  public synchronized boolean observe(Long hostProcessEpoch) {
    if (destroyed) return false;
    if (hostProcessEpoch == null || hostProcessEpoch.longValue() <= 0L) {
      if (observed == null) return false;
      observed = null;
      return true;
    }
    if (hostProcessEpoch.equals(observed)) return false;
    observed = hostProcessEpoch;
    return true;
  }
  public synchronized boolean isCurrent(Long hostProcessEpoch) {
    return !destroyed && observed != null && observed.equals(hostProcessEpoch);
  }
  public synchronized void destroy() {
    destroyed = true;
    observed = null;
  }
  /** No SessionStore or ToolRuntime native proof exists: always deny. */
  public synchronized boolean authorizeOriginalToolCall(String sessionId,
      String callId, Long claimedGeneration) {
    return false;
  }
}
"""

PROBE="""import com.dsh.android.p111.P111NativeProcessSnapshot;
public final class P111Probe {
  static void ck(boolean yes,String reason){if(!yes)throw new AssertionError(reason);}
  public static void main(String[] ignore) {
    P111NativeProcessSnapshot g=new P111NativeProcessSnapshot();
    ck(!g.observe(null),"initial_null_changed");
    ck(!g.isCurrent(null),"initial_null_accepted");
    ck(!g.observe(0L),"nonpositive_generation_accepted");
    ck(g.observe(1L),"first_real_generation_missing");
    ck(!g.observe(1L),"duplicate_ready_rotated");
    ck(g.isCurrent(1L),"real_generation_not_current");
    ck(!g.authorizeOriginalToolCall("session","pendingCall",1L),"forged_call_accepted");
    ck(g.observe(null),"dead_generation_not_revoked");
    ck(!g.isCurrent(1L),"old_dead_generation_current");
    ck(g.observe(2L),"replaced_process_epoch_not_changed");
    ck(!g.isCurrent(1L),"stale_original_generation_accepted");
    ck(g.isCurrent(2L),"current_host_generation_missing");
    ck(!g.authorizeOriginalToolCall("session","pendingCall",2L),"host_epoch_alone_authorized");
    g.destroy();
    ck(!g.isCurrent(2L),"destroy_kept_generation");
    ck(!g.observe(3L),"destroy_reactivated_process");
    ck(!g.authorizeOriginalToolCall("session","pendingCall",3L),"destroy_accepted_call");
    System.out.println("P111_ACTUAL_JAVA_PROCESS_SNAPSHOT_REVOKE=PASS");
    System.out.println("P111_DUPLICATE_READY_NO_REVOKE=PASS");
    System.out.println("P111_PROCESS_GENERATION_ALONE_NEVER_AUTHORIZES=PASS");
  }
}
"""

def replace_exact(source,old,new):
    if source.count(old)!=1:
        raise ValueError("P111_EXACT_ORIGINAL_SOURCE_ANCHOR="+str(source.count(old)))
    return source.replace(old,new)

def apply(root):
    activity=root/ACTIVITY
    boundary=root/BOUNDARY
    gate=root/GATE
    if not activity.is_file() or not boundary.is_file() or gate.exists():
        raise ValueError("P111_PINNED_BASE_OR_GATE_ALREADY_PRESENT")
    a=activity.read_text(encoding="utf-8")
    b=boundary.read_text(encoding="utf-8")
    a=replace_exact(a,
        "                p109TrustedToolHost.onOriginalEngineStateChanged()\n",
        "                // Read the actual original Process identity/Ready state\n"
        "                // from P110 EngineManager, never from Node or WebView.\n"
        "                p109TrustedToolHost.onOriginalEngineProcessStateChanged(\n"
        "                    engine.originalProcessEpochForNativeDiagnostics())\n")
    b=replace_exact(b,
        "import com.dsh.android.p102.P102TrustedToolGate\n",
        "import com.dsh.android.p102.P102TrustedToolGate\n"
        "import com.dsh.android.p111.P111NativeProcessSnapshot\n")
    b=replace_exact(b,
        "internal class P109OriginalToolHostBoundary {\n",
        "internal class P109OriginalToolHostBoundary {\n"
        "    private val p111ProcessSnapshot = P111NativeProcessSnapshot()\n")
    b=replace_exact(b,
        "    fun onOriginalEngineStateChanged() {\n"
        "        // Every state change revokes; P102 never receives bind initiation here.\n"
        "        port.onTrustedUiBackground()\n"
        "    }\n",
        "    fun onOriginalEngineProcessStateChanged(hostProcessEpoch: Long?) {\n"
        "        // Revoke only when actual original engine Process generation changes.\n"
        "        // A duplicate Activity Ready must not stop a still-running tool.\n"
        "        if (p111ProcessSnapshot.observe(hostProcessEpoch)) {\n"
        "            port.onTrustedUiBackground()\n"
        "        }\n"
        "    }\n")
    b=replace_exact(b,
        "    fun onOriginalActivityDestroyed() {\n"
        "        port.onTrustedUiBackground()\n",
        "    fun onOriginalActivityDestroyed() {\n"
        "        p111ProcessSnapshot.destroy()\n"
        "        port.onTrustedUiBackground()\n")
    activity.write_text(a,encoding="utf-8")
    boundary.write_text(b,encoding="utf-8")
    gate.parent.mkdir(parents=True,exist_ok=True)
    gate.write_text(JAVA,encoding="utf-8")
    print("P111_ACTUAL_ENGINE_PROCESS_TO_NATIVE_PORT_SOURCE=PASS")
    print("P111_STALE_OR_DEAD_ENGINE_REVOKES_NATIVE_PORT=PASS")
    print("P111_DUPLICATE_READY_DOES_NOT_REVOKE=PASS")
    print("P111_ORIGINAL_SESSION_CALL_VERIFIER_STILL_DENIES=YES")
    print("P111_NODE_BINDER_AND_APK=NOT_WIRED")

def selftest(root):
    if not (root/GATE).is_file():raise ValueError("P111_SOURCE_NOT_APPLIED")
    with tempfile.TemporaryDirectory() as tmp:
        probe=Path(tmp)/"P111Probe.java"
        probe.write_text(PROBE,encoding="utf-8")
        subprocess.run(["javac","-encoding","UTF-8","-d",tmp,str(root/GATE),str(probe)],check=True)
        subprocess.run(["java","-cp",tmp,"P111Probe"],check=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-dir",type=Path,required=True)
    p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    if args.selftest:selftest(args.upstream_dir)
    else:apply(args.upstream_dir)
