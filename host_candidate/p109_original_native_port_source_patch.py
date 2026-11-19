#!/usr/bin/env python3
"""P109 original Kotlin host + P102 native Messenger source compile-only attachment.
Reuses P108 patch on pinned MIT upstream in a disposable CI worktree.
DOES NOT register a worker, bind a service, authorize a tool, or create an APK.
"""
from pathlib import Path
import argparse
import subprocess
import shutil

ORIGINAL_ACTIVITY="app/src/main/java/com/dsh/android/MainActivity.kt"
BRIDGE_SOURCE="app/src/main/java/com/dsh/android/P109OriginalToolHostBoundary.kt"
COPIES=[
 ("host_candidate/p71_browser_runtime/src/com/dsh/android/p71/P71ToolReplyOnce.java",
  "app/src/main/java/com/dsh/android/p71/P71ToolReplyOnce.java"),
 ("host_candidate/p102_trusted_tool/src/com/dsh/android/p102/P102TrustedToolGate.java",
  "app/src/main/java/com/dsh/android/p102/P102TrustedToolGate.java"),
 ("host_candidate/p102_trusted_tool/android/com/dsh/android/p102/P102AndroidToolBinderPort.java",
  "app/src/main/java/com/dsh/android/p102/P102AndroidToolBinderPort.java"),
]
BRIDGE='''// Nonofficial compatibility source patch; upstream pht88888888/DSHAPP MIT notice preserved.
package com.dsh.android

import com.dsh.android.p102.P102AndroidToolBinderPort
import com.dsh.android.p102.P102TrustedToolGate

/**
 * Connects the original Android Activity lifecycle to the P102 native
 * Messenger implementation solely for compile/source integration.
 *
 * No original SessionStore/ToolRuntime provenance reaches the trusted host.
 * Therefore: NO native UI approval, NO executor, NO accepted original call,
 * NO worker Service registration, NO outbound Messenger binding.
 */
internal class P109OriginalToolHostBoundary {
    private val port = P102AndroidToolBinderPort(
        P102AndroidToolBinderPort.NativeApprovalUi { _, _ ->
            // Fail closed: never display an approval for a fabricated call.
        },
        P102TrustedToolGate.TrustedExecutor { _, _ ->
            false // No device tool execution until real ownership exists.
        },
        P102TrustedToolGate.OriginalCallVerifier { _, _ ->
            false // Original still-live SessionStore + pending ToolRuntime NOT WIRED.
        }
    )

    fun onOriginalEngineStateChanged() {
        // Every state change revokes; P102 never receives bind initiation here.
        port.onTrustedUiBackground()
    }

    fun onOriginalActivityDestroyed() {
        port.onTrustedUiBackground()
    }
}
'''
def replace_once(s,old,new):
    if s.count(old)!=1:raise ValueError("P109_EXACT_PINNED_ACTIVITY_ANCHOR_REQUIRED")
    return s.replace(old,new)

def apply(root,changes):
    src=root/ORIGINAL_ACTIVITY
    dest=root/BRIDGE_SOURCE
    if not src.is_file() or dest.exists():raise ValueError("P109_PINNED_SOURCE_REQUIRED")
    s=src.read_text(encoding="utf-8")
    s=replace_once(s,"    private val p108OriginalOwnerEpoch = P108OriginalOwnerEpochGate()\n",
         "    private val p108OriginalOwnerEpoch = P108OriginalOwnerEpochGate()\n"+
         "    private val p109TrustedToolHost = P109OriginalToolHostBoundary()\n")
    s=replace_once(s,
      "                p108OriginalOwnerEpoch.observeEngineState(state is EngineManager.State.Ready)\n",
      "                p108OriginalOwnerEpoch.observeEngineState(state is EngineManager.State.Ready)\n"+
      "                p109TrustedToolHost.onOriginalEngineStateChanged()\n")
    s=replace_once(s,
      "        p108OriginalOwnerEpoch.onActivityDestroyed()\n",
      "        p108OriginalOwnerEpoch.onActivityDestroyed()\n"+
      "        p109TrustedToolHost.onOriginalActivityDestroyed()\n")
    for original,target in COPIES:
        path=changes/original;out=root/target
        if not path.is_file() or out.exists():raise ValueError("P109_EXACT_JAVA_FILE_GATE_"+target)
        out.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,out)
    src.write_text(s,encoding="utf-8")
    dest.write_text(BRIDGE,encoding="utf-8")
    print("P109_ORIGINAL_ACTIVITY_LIFECYCLE_TO_P102_PORT_SOURCE_HOOK=PASS")
    print("P109_ACTUAL_P102_NATIVE_JAVA_SOURCES_INCLUDED=PASS")
    print("P109_ORIGINAL_SESSIONSTORE_VERIFIER_DEFAULT_DENY=PASS")
    print("P109_NATIVE_EXECUTOR_DEFAULT_DENY=PASS")
    print("P109_ISOLATED_WORKER_PRODUCTION=NOT_WIRED")
    print("P109_APK_OR_SIGNING=NONE")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--upstream-dir",type=Path,required=True)
    parser.add_argument("--changes-dir",type=Path,required=True)
    args=parser.parse_args()
    apply(args.upstream_dir,args.changes_dir)
