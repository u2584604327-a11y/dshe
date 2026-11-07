#!/usr/bin/env python3
"""P108 bounded, pinned MIT-original MainActivity engine-epoch patch.
ONLY changes a temporary checkout of pht88888888/DSHAPP pinned revision.
No APK/DEX or signing operation. Tool calls remain default DENY.
"""
import argparse
from pathlib import Path
import tempfile

HOST="app/src/main/java/com/dsh/android/MainActivity.kt"
BOUNDARY="app/src/main/java/com/dsh/android/P108OriginalOwnerEpochGate.kt"
SOURCE=(
    "// Derived compatibility candidate from pht88888888/DSHAPP (MIT).\\n"
    "// Original copyright (c) 2026 pht88888888; original MIT notice retained.\\n"
    "package com.dsh.android\\n\\n"
    "/** Engine lifecycle evidence ONLY. Not a live SessionStore or pending ToolRuntime call proof.\\n"
    " * Native permission is permanently DENIED until a separate trustworthy production\\n"
    " * OriginalCallVerifier is implemented and validated. No Node/JS/file mailbox claims count.\\n"
    " */\\n"
    "internal class P108OriginalOwnerEpochGate {\\n"
    "    private var epoch: Long = 0\\n"
    "    private var ready: Boolean = false\\n"
    "    private var revoked: Boolean = false\\n\\n"
    "    @Synchronized fun observeEngineState(isReady: Boolean) {\\n"
    "        if (revoked || ready == isReady) return\\n"
    "        if (epoch == Long.MAX_VALUE) { revoked = true; ready = false; return }\\n"
    "        epoch++\\n"
    "        ready = isReady\\n"
    "    }\\n\\n"
    "    @Synchronized fun onActivityDestroyed() {\\n"
    "        ready = false\\n"
    "        revoked = true\\n"
    "        if (epoch != Long.MAX_VALUE) epoch++\\n"
    "    }\\n\\n"
    "    @Synchronized fun currentEpochForNativeDiagnostics(): Long = epoch\\n\\n"
    "    /** True is impossible without a future independently proven original session+call. */\\n"
    "    @Synchronized fun authorizeOriginalToolCall(\\n"
    "        originalSessionId: String?, originalCallId: String?, claimedEpoch: Long\\n"
    "    ): Boolean = false\\n"
    "}\\n"
).replace("\\n","\n")

def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1: raise ValueError("P108_EXPECTED_UPSTREAM_ANCHOR_COUNT_"+str(source.count(old)))
    return source.replace(old,new)

def patch(root: Path):
    main=root/HOST
    boundary=root/BOUNDARY
    if not main.is_file() or boundary.exists():
        raise ValueError("P108_EXACT_PINNED_SOURCE_OR_NEW_FILE_PRECONDITION")
    source=main.read_text(encoding="utf-8")
    source=replace_once(
        source,"    private lateinit var engine: EngineManager\n",
        "    private lateinit var engine: EngineManager\n"
        "    // No native tool permission is granted by this lifecycle observer.\n"
        "    private val p108OriginalOwnerEpoch = P108OriginalOwnerEpochGate()\n")
    source=replace_once(
        source,"            engine.state.collect { state ->\n                when (state) {",
        "            engine.state.collect { state ->\n"
        "                // Tracks original host process transitions, not tool-call ownership.\n"
        "                p108OriginalOwnerEpoch.observeEngineState(state is EngineManager.State.Ready)\n"
        "                when (state) {")
    source=replace_once(
        source,"    override fun onDestroy() {\n"
               "        // 引擎跟随进程存活，这里不停止，避免转屏/重建时反复冷启动。",
        "    override fun onDestroy() {\n"
        "        // Revoke this Activity's epoch without stopping original Node/AgentLoop.\n"
        "        p108OriginalOwnerEpoch.onActivityDestroyed()\n"
        "        // 引擎跟随进程存活，这里不停止，避免转屏/重建时反复冷启动.")
    main.write_text(source,encoding="utf-8")
    boundary.write_text(SOURCE,encoding="utf-8")
    assert source.count("p108OriginalOwnerEpoch.observeEngineState") == 1
    assert source.count("p108OriginalOwnerEpoch.onActivityDestroyed") == 1
    assert "): Boolean = false" in SOURCE
    print("P108_ORIGINAL_MAINACTIVITY_STATEFLOW_HOOK=PASS")
    print("P108_ORIGINAL_MAINACTIVITY_ONDESTROY_REVOKE=PASS")
    print("P108_UNVERIFIED_TOOL_CALL_DEFAULT_DENY=PASS")
    print("P108_ORIGINAL_AGENTLOOP_NODE_UNMODIFIED=YES")
    print("P108_ENGINE_SERVICE_BINDER_PRODUCTION=NOT_WIRED")

def selftest():
    with tempfile.TemporaryDirectory() as d:
        root=Path(d);p=root/HOST;p.parent.mkdir(parents=True,exist_ok=True)
        text=("    private lateinit var engine: EngineManager\n"+
              "            engine.state.collect { state ->\n                when (state) {\n"+
              "    override fun onDestroy() {\n"
              "        // 引擎跟随进程存活，这里不停止，避免转屏/重建时反复冷启动。\n")
        p.write_text(text,encoding="utf-8")
        patch(root)
        try:patch(root)
        except ValueError:pass
        else:raise AssertionError("P108_REPLAY_OF_SOURCE_PATCH_NOT_REJECTED")
        assert "onActivityDestroyed()" in p.read_text(encoding="utf-8")
        assert "): Boolean = false" in (root/BOUNDARY).read_text(encoding="utf-8")
    print("P108_SOURCE_PATCH_SELFTEST=PASS")

if __name__=="__main__":
    cli=argparse.ArgumentParser()
    cli.add_argument("--upstream-dir",type=Path)
    cli.add_argument("--selftest",action="store_true")
    a=cli.parse_args()
    if a.selftest: selftest()
    else:
        if a.upstream_dir is None:raise SystemExit("P108_NEED_PINNED_UPSTREAM_DIR")
        patch(a.upstream_dir)
