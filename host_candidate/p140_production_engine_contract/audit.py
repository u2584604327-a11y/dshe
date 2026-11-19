#!/usr/bin/env python3
"""P140: pinned-original three-launch-path & readiness blocker, source read-only.
P51 proved a real original-ELF synthetic isolated test on user ARM64 device.
It did NOT prove original app's EngineManager production-ready lifecycle.
"""
import argparse
import pathlib
import subprocess

UPSTREAM = "4dddb12fd076d052e788a16638a658b7a447b669"
ENGINE = "app/src/main/java/com/dsh/android/EngineManager.kt"

def require(condition, marker):
    if not condition:
        raise AssertionError("P140_BLOCKED_" + marker)

def verify(engine, p37, p50, p74, p75, manifest):
    # Audit the exact, unmodified upstream, NOT Kotlin rewritten by test harness.
    require(engine.count("val pb = ProcessBuilder(") == 3,
            "THREE_ORIGINAL_PROCESSBUILDERS_CHANGED")
    require(engine.count("val proc = pb.start()") == 2,
            "PROBE_AND_DUMP_SPAWN_DRIFT")
    require(engine.count("            pb.start()") == 1,
            "PRODUCTION_START_SPAWN_DRIFT")
    a = engine.index("private fun probeBoot(")
    b = engine.index("private fun runDumpConfig(")
    c = engine.index("    suspend fun start()")
    require(len({a,b,c}) == 3, "MISSING_ENGINE_PATH")
    # The source is ~450 KB; function declaration order is not execution order.
    probe = engine[a:a+12000]
    dump = engine[b:b+7000]
    start = engine[c:c+48000]
    require("ProcessBuilder(cmd)" in probe
            and ".redirectErrorStream(true)" in probe
            and "val proc = pb.start()" in probe,
            "PROBE_BOOT_CONTRACT_CHANGED")
    require('ProcessBuilder(' in dump
            and '"--dump-config"' in dump
            and "val proc = pb.start()" in dump
            and "proc.errorStream" in dump,
            "DUMP_CONFIG_CONTRACT_CHANGED")
    require("ProcessBuilder(cmd)" in start
            and ".redirectErrorStream(true)" in start
            and "val proc = try" in start
            and "pb.start()" in start
            and "process = proc" in start
            and "proc.inputStream.bufferedReader()" in start
            and "val urlPattern = URL_PATTERN" in start
            and "_state.value = State.Ready(url)" in start,
            "PRODUCTION_ENGINE_LIFECYCLE_DRIFT")
    require('Regex("""dsh web: (http://127' in engine
            and engine.count("URL_PATTERN.containsMatchIn(line)") >= 1,
            "REAL_HTTP_TOKEN_URL_READY_REGEX_MISSING")
    require('P37RemoteProcess' not in engine, "UPSTREAM_ALREADY_WIRED_REVIEW_REQUIRED")
    require("P37_UNAUDITED_STDIN_DENIED" in p37
            and "getErrorStream() { return stderr;" in p37
            and "getInputStream() { return stdout;" in p37
            and "onTransportLost()" in p37,
            "P37_STREAM_PROXY_CAPABILITIES_CHANGED")
    require("P74_FIXTURE_ONLY_REAL_ENGINE_ARGV_NOT_AUTHORIZED" in p74
            and '"/system/bin/id".equals(cmd.get(0))' in p74,
            "P74_FIXTURE_UNEXPECTEDLY_ESCALATED")
    require("P75_PRODUCTION_ARGV_NOT_AUTHORIZED" in p75
            and '"/system/bin/id".equals(args.get(0))' in p75,
            "P75_FIXTURE_UNEXPECTEDLY_ESCALATED")
    require("private static final String FIXED_JS=" in p50
            and "'UID='+" in p50
            and "P50_ORIGINAL_NODE_PRODUCTION_SCRIPTS" not in p50,
            "P50_SYNTHETIC_NODE_SCOPE_DRIFT")
    require('SIDECAR="com.dsh.p51.isolatedprobe"' in manifest
            and 'ORIGINAL="com.dsh.android"' in manifest,
            "DISTINCT_PACKAGE_SCOPE_CHANGED")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--original",type=pathlib.Path,required=True)
    ap.add_argument("--changes",type=pathlib.Path,required=True)
    a=ap.parse_args()
    actual=subprocess.check_output(
        ["git","-C",str(a.original),"rev-parse","HEAD"],text=True).strip()
    require(actual==UPSTREAM,"ORIGINAL_MIT_SHA_NOT_PINNED")
    require(not subprocess.check_output(
        ["git","-C",str(a.original),"status","--porcelain"],text=True).strip(),
        "ORIGINAL_WORKTREE_DIRTY")
    base=a.changes/"host_candidate"
    inputs=[
        (a.original/ENGINE).read_text(encoding="utf-8"),
        (base/"p37_remote_process/src/com/dsh/p37/P37RemoteProcess.java").read_text(),
        (base/"p50_original_arm64_node/android/com/dsh/android/p50/P50OriginalNodeFixedChild.java").read_text(),
        (base/"p74_engine_fixture/src/com/dsh/android/p74/P74OriginalEngineFixtureHandoff.java").read_text(),
        (base/"p75_engine_rendezvous/src/com/dsh/android/p75/P75EngineStartRendezvous.java").read_text(),
        (base/"p51_side_by_side/p51_manifest.py").read_text(),
    ]
    verify(*inputs)
    # The test's own critical negative controls must be caught, not silently pass.
    bad=list(inputs)
    bad[0]=bad[0].replace("val urlPattern = URL_PATTERN",
                          "val urlPattern = Regex(\"READY\")",1)
    try:
        verify(*bad)
    except AssertionError as fail:
        require("PRODUCTION_ENGINE_LIFECYCLE_DRIFT" in str(fail),
                "NEGATIVE_URL_FIXTURE_GATE_WRONG_FAILURE")
    else:
        raise AssertionError("P140_BLOCKED_SYNTHETIC_READY_NOT_REJECTED")
    bad=list(inputs)
    bad[4]=bad[4].replace("P75_PRODUCTION_ARGV_NOT_AUTHORIZED",
                          "P75_ALLOW_PRODUCTION_ARGV",1)
    try:
        verify(*bad)
    except AssertionError as fail:
        require("P75_FIXTURE_UNEXPECTEDLY_ESCALATED" in str(fail),
                "NEGATIVE_P75_GATE_WRONG_FAILURE")
    else:
        raise AssertionError("P140_BLOCKED_FIXTURE_ESCALATION_NOT_REJECTED")
    print("P140_PINNED_REAL_ORIGINAL_ENGINE_SOURCE=PASS")
    print("P140_ORIGINAL_ENGINE_PROCESSBUILDER_ENTRYPOINTS=3_UNWIRED")
    print("P140_PROBE_CONFIG_PRODUCTION_PATHS_DISTINCT=PASS")
    print("P140_PRODUCTION_URL_TOKEN_READY_NOT_SYNTHETIC_READY=PASS")
    print("P140_P37_STDOUT_STDERR_SPLIT_AND_STDIN_DENY=PASS")
    print("P140_P74_P75_ONLY_SYSTEM_ID_FIXTURE=PASS")
    print("P140_P51_DISTINCT_APP_NOT_ORIGINAL_ENGINE=PASS")
    print("P140_NEGATIVE_READINESS_AND_EXECUTION_GATE_TESTS=2_PASS")
    print("P140_ORIGINAL_NODE_ARM64_ISOLATED_SYNTHETIC_PHONE_PROOF=USER_REPORTED")
    print("P140_PRODUCTION_BROKER_ARGV_FD_SESSION_READY=NOT_WIRED")
    print("P140_P109_SENSITIVE_NATIVE_TOOLS=DENY_ALL")
    print("P140_FORMAL_V139=BLOCKED")

if __name__ == "__main__":
    main()
