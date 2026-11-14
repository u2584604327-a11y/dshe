#!/usr/bin/env python3
"""P142 scope-limited patch to pinned *original* MIT Kotlin source in CI only.
Changes exactly three ProcessBuilder.start() sites, not engine state,
arguments, env, URL parser, stdout consumer, original signer, or APK.
"""
import argparse
from pathlib import Path
import shutil
import subprocess

FILE="app/src/main/java/com/dsh/android/EngineManager.kt"
GATE="app/src/main/java/com/dsh/android/p142/P142OriginalEngineSpawnSeam.java"
FROM="host_candidate/p142_original_three_seams/src/com/dsh/android/p142/P142OriginalEngineSpawnSeam.java"
P149_SOURCE="host_candidate/p149_prelaunch_witness/src/com/dsh/android/p149/P149OriginalBuilderWitness.java"
P149_TARGET="app/src/main/java/com/dsh/android/p149/P149OriginalBuilderWitness.java"
PINNED="4dddb12fd076d052e788a16638a658b7a447b669"
REPLACEMENTS=(
  ("            val proc = pb.start()\n"
   "            val lines = java.util.Collections.synchronizedList",
   "            val proc = com.dsh.android.p142.P142OriginalEngineSpawnSeam.probeOrDeny(pb)\n"
   "            val lines = java.util.Collections.synchronizedList"),
  ("            val proc = pb.start()\n"
   "            // ⚠️ 必须**并发**读走两个流",
   "            val proc = com.dsh.android.p142.P142OriginalEngineSpawnSeam.configOrDeny(pb)\n"
   "            // ⚠️ 必须**并发**读走两个流"),
  ("        val proc = try {\n"
   "            pb.start()\n"
   "        } catch (t: Throwable) {",
   "        val proc = try {\n"
   "            com.dsh.android.p142.P142OriginalEngineSpawnSeam.primaryOrDeny(pb)\n"
   "        } catch (t: Throwable) {")
)

def transform(text):
    for old,new in REPLACEMENTS:
        if text.count(old)!=1 or text.count(new)!=0:
            raise ValueError("P142_PINNED_ENGINE_SPAWN_ANCHOR_DRIFT")
        text=text.replace(old,new)
    if text.count("P142OriginalEngineSpawnSeam.")!=3:
        raise ValueError("P142_THREE_DISTINCT_INTERCEPTIONS_REQUIRED")
    if text.count("val proc = pb.start()") or "            pb.start()" in text:
        raise ValueError("P142_ORIGINAL_HOST_SPAWN_REMAINS")
    if text.count("val urlPattern = URL_PATTERN")!=1 or \
       "dsh web: (http://127" not in text:
        raise ValueError("P142_ORIGINAL_READY_PREDICATE_DRIFT")
    return text

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--upstream-dir",type=Path,required=True)
    p.add_argument("--changes-dir",type=Path,required=True)
    a=p.parse_args()
    root=a.upstream_dir
    require=subprocess.check_output(["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()
    if require!=PINNED:raise ValueError("P142_SOURCE_SHA_NOT_PINNED")
    engine=root/FILE
    target=root/GATE
    if target.exists() or not engine.is_file():raise ValueError("P142_ORIGINAL_SOURCE_REQUIRED")
    before=engine.read_text(encoding="utf-8")
    after=transform(before)
    src=a.changes_dir/FROM
    if not src.is_file():raise ValueError("P142_GATE_SOURCE_MISSING")
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(src,target)
    p149_target=root/P149_TARGET
    p149_source=a.changes_dir/P149_SOURCE
    if p149_target.exists() or not p149_source.is_file():
        raise ValueError("P149_EXACT_JAVA_WITNESS_REQUIRED")
    p149_target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(p149_source,p149_target)
    engine.write_text(after,encoding="utf-8")
    if before.replace(REPLACEMENTS[0][0],REPLACEMENTS[0][1]) \
             .replace(REPLACEMENTS[1][0],REPLACEMENTS[1][1]) \
             .replace(REPLACEMENTS[2][0],REPLACEMENTS[2][1])!=after:
        raise ValueError("P142_OUTSIDE_THREE_SPAWN_SITES_MODIFIED")
    print("P142_PINNED_ORIGINAL_KOTLIN_THREE_SPAWN_CALLS_INTERPOSED=PASS")
    print("P142_MAIN_PROBE_CONFIG_KEEP_DISTINCT_SEMANTICS=PASS")
    print("P142_ORIGINAL_URL_READY_CONSUMER_UNMODIFIED=PASS")
    print("P142_NO_HOST_PROCESSBUILDER_START_FROM_ENGINE=PASS")
    print("P142_ISOLATED_BROKER_RUNTIME=NOT_WIRED")
    print("P142_ORIGINAL_PRODUCTION_ENGINE=DENIED_UNTIL_BROKER")

if __name__=="__main__":main()
