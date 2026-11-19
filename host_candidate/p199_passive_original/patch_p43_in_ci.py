#!/usr/bin/env python3
"""P199 original-derived Android35 one-shot CI patch; strict two-file scope."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
ACTIVITY="host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java"
BUILDER="host_candidate/p43_original_service/build_embedded_emulator_apk.sh"
OBSERVER="host_candidate/p199_passive_original/android/com/dsh/android/p199/P199PassiveOriginalWitness.java"
EXPECTED={
    ACTIVITY:"8a83ef4c53c8e527f604023ab5eec2be8f2e12a9",
    BUILDER:"62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f",
}
def git(*args):
    return subprocess.check_output(["git",*args],text=True,
                                   stderr=subprocess.DEVNULL).strip()
def once(s,old,new,tag):
    if s.count(old)!=1:raise RuntimeError("P199_PINNED_ANCHOR_"+tag)
    return s.replace(old,new)

def patch_activity(s):
    s=once(s,"import com.dsh.android.p151.P151OriginalEngineStateSampler;",
       "import com.dsh.android.p151.P151OriginalEngineStateSampler;\n"
       "import com.dsh.android.p199.P199PassiveOriginalWitness;","import")
    s=once(s,"  @Override public void onCreate(Bundle state){\n    super.onCreate(state);",
       """  @Override public void onCreate(Bundle state){
    super.onCreate(state);
    // P199 ONLY in SHA-pinned disposable original-derived emulator app.
    // BEFORE P43's synthetic P40->P47 call, isolated HELLO and any P43 tools.
    if(getIntent()!=null &&
       getIntent().getBooleanExtra("p199_passive_original",false)){
      P199PassiveOriginalWitness.start(this);
      return;
    }""","passive_before_synthetic")
    s=once(s,"  @Override protected void onDestroy(){",
       "  @Override protected void onDestroy(){\n"
       "    P199PassiveOriginalWitness.cancel(this);","destroy")
    return s

def patch_builder(s):
    old="  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n"
    return once(s,old,old+
      "  host_candidate/p199_passive_original/android/com/dsh/android/p199/P199PassiveOriginalWitness.java \\\n",
      "builder")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--ci",action="store_true")
    args=parser.parse_args()
    if not args.ci:
        raise RuntimeError("P199_CI_ONLY")
    if (os.environ.get("GITHUB_ACTIONS")!="true" or
        os.environ.get("GITHUB_REPOSITORY")!=REPO or
        os.environ.get("GITHUB_EVENT_NAME")!="pull_request"):
        raise RuntimeError("P199_CI_PR_SCOPE")
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr=event.get("pull_request") or {}
    head=pr.get("head") or {}
    if(pr.get("number")!=80 or head.get("ref")!=BRANCH or
       (head.get("repo") or {}).get("full_name")!=REPO):
        raise RuntimeError("P199_ORIGINAL_PR_SCOPE")
    root=Path(git("rev-parse","--show-toplevel")).resolve()
    if root!=Path.cwd().resolve() or git("status","--porcelain"):
        raise RuntimeError("P199_REPOSITORY_DIRTY_OR_WRONG")
    if not git("remote","get-url","origin").rstrip(".git").endswith(REPO):
        raise RuntimeError("P199_ORIGIN_MISMATCH")
    if not Path(OBSERVER).is_file():
        raise RuntimeError("P199_PASSIVE_OBSERVER_MISSING")
    changes={}
    for path,sha in EXPECTED.items():
        if git("hash-object",path)!=sha:
            raise RuntimeError("P199_SOURCE_BLOB_SHA_MISMATCH")
        old=Path(path).read_text()
        changes[path]=patch_activity(old) if path==ACTIVITY else patch_builder(old)
    for path,data in changes.items():
        Path(path).write_text(data)
    if set(git("diff","--name-only").splitlines())!=set(changes):
        raise RuntimeError("P199_CI_PATCH_SCOPE_DRIFT")
    print("P199_CI_ONLY_TWO_ORIGINAL_TEST_FILES_PATCHED=PASS")
    print("P199_P43_SYNTHETIC_BRIDGE_WILL_NOT_BE_INVOKED=PASS")
    print("P199_PRODUCTION_SOURCE_APK_OR_NODE_MODIFIED=NO")

if __name__=="__main__":
    try:main()
    except Exception:
        print("P199_CI_PATCH_FAIL_CLOSED",file=sys.stderr)
        sys.exit(2)
