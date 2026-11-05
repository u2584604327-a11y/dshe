#!/usr/bin/env python3
"""P209 temporary original-P47-gate final-DENY witness, strict read-only source."""
import argparse, json, os, subprocess, sys
from pathlib import Path
REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
GATE=Path("host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java")
GATE_BLOB="44cd38245dc87b9eff960b15dc520e60a2754c2c"
BUILDER=Path("host_candidate/p43_original_service/build_embedded_emulator_apk.sh")
TMP=Path(".p209tmp/P47LaunchGate.java")
BEFORE="P74_P47_GATE_SOURCE="+str(GATE)+"\n"
AFTER="P74_P47_GATE_SOURCE=.p209tmp/P47LaunchGate.java\n"
METHOD="  public static Process startOrDeny(ProcessBuilder builder) throws IOException {\n"
NEXT="\n  /** P182:"
SHAPE="    Shape shape=categorize(builder);\n"
THROW='    throw new IOException("P47_ISOLATED_SUPERVISOR_UNAVAILABLE_NO_HOST_FALLBACK");\n'
ENTER='    android.util.Log.i("P209_GATE","P209_P47_ENTER_UID="+android.os.Process.myUid());\n'
STACK=('    android.util.Log.i("P209_GATE", '
    'com.dsh.android.p150.P150OriginalCoroutineObserver.isOriginalStack('
    'Thread.currentThread().getStackTrace()) ? '
    '"P209_ORIGINAL_CALLSTACK=PASS" : "P209_ORIGINAL_CALLSTACK=OTHER");\n')
FINAL='    android.util.Log.i("P209_GATE","P209_P47_FINAL_DENY_UID="+android.os.Process.myUid());\n'
class Deny(Exception):pass
def need(v,code):
    if not v:raise Deny("P209_DENY_"+code)
def git(*args):
    return subprocess.check_output(["git",*args],text=True,stderr=subprocess.DEVNULL).strip()
def patch_gate(s):
    need(s.count(METHOD)==1,"ONE_PRIMARY_METHOD")
    need(all(x not in s for x in (ENTER,STACK,FINAL)),"NOT_ALREADY_MARKED")
    a=s.index(METHOD);b=s.find(NEXT,a)
    need(b>a and b-a<9000,"PRIMARY_METHOD_BOUNDS")
    m=s[a:b]
    need(m.count(SHAPE)==1 and m.count(THROW)==1 and
         m.index(SHAPE)<m.index(THROW),"PRIMARY_ORIGINAL_DENY_ANCHORS")
    changed=m.replace(SHAPE,ENTER+SHAPE,1).replace(
        THROW,STACK+FINAL+THROW,1)
    out=s[:a]+changed+s[b:]
    need(out.replace(ENTER,"",1).replace(STACK,"",1).replace(FINAL,"",1)==s,
         "THREE_ADDENDA_ONLY")
    need(all(out.count(x)==1 for x in (ENTER,STACK,FINAL)),
         "MARKER_UNIQUENESS")
    return out
def patch_builder(s):
    need(s.count(BEFORE)==1 and s.count(AFTER)==0 and
         "P208_CI_METHOD_ENTRY_ONLY" in s and
         "p208/P208StartCoroutineWitness.java" in s,
         "PINNED_P208_BUILDER_REQUIRED")
    out=s.replace(BEFORE,AFTER,1)
    need(out.replace(AFTER,BEFORE,1)==s,"ONLY_GATE_SOURCE_SWITCH")
    return out
def scope():
    need(os.environ.get("GITHUB_ACTIONS")=="true" and
         os.environ.get("GITHUB_REPOSITORY")==REPO and
         os.environ.get("GITHUB_EVENT_NAME")=="pull_request","ONLY_CI")
    e=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    p=e.get("pull_request") or {};h=p.get("head") or {}
    need(p.get("number")==80 and h.get("ref")==BRANCH and
         (h.get("repo") or {}).get("full_name")==REPO,"EXACT_PR")
    for k,v in (("P209_FINAL_DENY_ONLY","1"),("P208_CI_METHOD_ENTRY_ONLY","1"),
         ("P47_NO_HOST_FALLBACK","1"),("P181_THREE_ORIGINAL_START_DENY","1"),
         ("P49_NODE_STAGE","0"),("P51_SIDE_BY_SIDE","0"),
         ("P74_FIXTURE_ENGINE_BRIDGE","0"),("P75_RENDEZVOUS_FIXTURE","0")):
        need(os.environ.get(k,"0")==v,"SAFE_FLAG_"+k)
    need(git("hash-object",str(GATE))==GATE_BLOB,"PINNED_REAL_GATE")
    need(not TMP.exists(),"TMP_GATE_NOT_PREEXISTING")
    need(git("diff","--name-only").splitlines()==[str(BUILDER)],
         "ONLY_P208_TEMP_BUILDER_CHANGED")
def prepare():
    scope()
    src=GATE.read_text()
    TMP.parent.mkdir(parents=True,exist_ok=True)
    TMP.write_text(patch_gate(src))
    BUILDER.write_text(patch_builder(BUILDER.read_text()))
    need(GATE.read_text()==src and
         TMP.read_text().replace(ENTER,"",1).replace(STACK,"",1).
             replace(FINAL,"",1)==src,"REAL_GATE_NOT_EDITED")
    need(git("diff","--name-only").splitlines()==[str(BUILDER)],
         "WORKTREE_SCOPE")
    print("P209_SHA_PINNED_REAL_P47_SOURCE_UNCHANGED=PASS")
    print("P209_ONLY_DISPOSABLE_GATE_THREE_FIXED_LOG_MARKERS=PASS")
    print("P209_TEMP_BUILDER_SOURCE_SWITCH_ONLY=PASS")
def main():
    a=argparse.ArgumentParser();a.add_argument("--prepare",required=True,action="store_true");a.parse_args()
    try:prepare()
    except Deny as e:print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:print("P209_UNEXPECTED_TEST_PREPARE_ERROR",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
