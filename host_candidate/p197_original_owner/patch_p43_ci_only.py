#!/usr/bin/env python3
"""P197 real Android35 receipt fixture, CI-only and immutable-source-pinned."""
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
P48="host_candidate/p48_process_proxy/android/com/dsh/android/p48/P48HostProcessProbe.java"
HELPER="host_candidate/p197_original_owner/android/com/dsh/android/p197/P197AndroidHostEpochProbe.java"
ANDROID_OWNER="host_candidate/p197_original_owner/android/com/dsh/android/p197/P197AndroidOwnerInspector.java"
HOST_LEDGER="host_candidate/p197_original_owner/src/com/dsh/android/p197/P197HostGeneration.java"
RECEIPT="host_candidate/p184_verified_child_receipt/src/com/dsh/android/p68/P184ChildStartReceipt.java"
EXPECTED={ACTIVITY:"8a83ef4c53c8e527f604023ab5eec2be8f2e12a9",
          BUILDER:"62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f",
          P48:"69095b4d2020b1ddcd37c413a6065dce47073e5a",
          RECEIPT:"3dac8177db81cb48ec85612b6eb31ff61ed4ee98"}
def git(*args):
    return subprocess.check_output(["git",*args],text=True,stderr=subprocess.STDOUT).strip()
def once(s,old,new,label):
    if s.count(old)!=1:raise RuntimeError("P197_SOURCE_ANCHOR_"+label+"_DRIFT")
    return s.replace(old,new)
def patch_activity(s):
    s=once(s,"import com.dsh.android.p156.P156OriginalAppLibProbe;",
        "import com.dsh.android.p156.P156OriginalAppLibProbe;\n"
        "import com.dsh.android.p197.P197AndroidHostEpochProbe;","import")
    s=once(s,"  private volatile java.lang.Process p75AuthenticatedProxy;",
        "  private volatile java.lang.Process p75AuthenticatedProxy;\n"
        "  private P197AndroidHostEpochProbe p197;","field")
    s=once(s,"      if(remote!=null && p48==null) {",
        """      // P197 only in a fresh emulator with the original P43 HELLO/FD hash
      // already checked and the original P47 main-DEX host deny gate intact.
      if(remote!=null && getIntent()!=null &&
         getIntent().getBooleanExtra("p197_owner_generation",false)){
        try {
          p197=new P197AndroidHostEpochProbe(P43ProbeActivity.this,
              remote,session,line->log(line));
          p197.start();
        }catch(SecurityException denied){
          // Only constant allowlisted categories; never raw exception text,
          // instance identity, UID/PID, session or original app private data.
          String code=denied.getMessage();
          if("P197_ORIGINAL_SINGLETON_NOT_ACTIVE".equals(code))
            log("P197_ANDROID35_SINGLETON_NOT_INITIALIZED=DENY");
          else if("P197_ORIGINAL_SINGLETON_REFLECTION_DENIED".equals(code) ||
                  "P197_UNEXPECTED_ORIGINAL_SINGLETON_FIELD".equals(code))
            log("P197_ANDROID35_SINGLETON_REFLECTION=DENY");
          else
            log("P197_ANDROID35_HOST_OWNER_PRECONDITION=DENY");
          fail("P197_HOST_OWNER_EPOCH_NOT_ESTABLISHED");
        }
        return; // no P50, general shell or original Node execution
      }
      if(remote!=null && p48==null) {""","start")
    s=once(s,
        '    @Override public void onServiceDisconnected(ComponentName n){fail("SERVICE_DISCONNECTED");}',
        '    @Override public void onServiceDisconnected(ComponentName n){'
        'if(p197!=null)p197.close();fail("SERVICE_DISCONNECTED");}',
        "disconnect")
    s=once(s,
        '    @Override public void onBindingDied(ComponentName n){fail("BINDING_DIED");}',
        '    @Override public void onBindingDied(ComponentName n){'
        'if(p197!=null)p197.close();fail("BINDING_DIED");}',
        "death")
    s=once(s,
        '    @Override public void onNullBinding(ComponentName n){fail("NULL_BINDING");}',
        '    @Override public void onNullBinding(ComponentName n){'
        'if(p197!=null)p197.close();fail("NULL_BINDING");}',
        "null")
    s=once(s,
        "  @Override protected void onDestroy(){\n    if(getIntent()!=null",
        "  @Override protected void onDestroy(){\n"
        "    if(p197!=null)p197.close();\n    if(getIntent()!=null",
        "destroy")
    return s
def patch_builder(s):
    key="  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n"
    return once(s,key,key+"".join("  "+name+" \\\n" for name in (HELPER,ANDROID_OWNER,HOST_LEDGER)),"builder")
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--ci",action="store_true")
    args=ap.parse_args()
    if not args.ci:raise RuntimeError("P197_REQUIRES_CI_FLAG")
    if (os.environ.get("GITHUB_ACTIONS")!="true" or
        os.environ.get("GITHUB_REPOSITORY")!=REPO or
        os.environ.get("GITHUB_EVENT_NAME")!="pull_request"):
        raise RuntimeError("P197_NOT_APPROVED_WORKFLOW")
    e=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr=e.get("pull_request") or {}
    head=pr.get("head") or {}
    if(pr.get("number")!=80 or head.get("ref")!=BRANCH or
       (head.get("repo") or {}).get("full_name")!=REPO):
        raise RuntimeError("P197_PR_SOURCE_SCOPE_MISMATCH")
    root=Path(git("rev-parse","--show-toplevel")).resolve()
    if(root!=Path.cwd().resolve() or git("status","--porcelain")):
        raise RuntimeError("P197_DIRTY_OR_WRONG_ROOT")
    remote=git("remote","get-url","origin")
    if not(remote.endswith(REPO) or remote.endswith(REPO+".git")):
        raise RuntimeError("P197_WRONG_ORIGIN")
    for helper in (HELPER,ANDROID_OWNER,HOST_LEDGER):
        if not Path(helper).is_file():
            raise RuntimeError("P197_HELPER_MISSING")
    data={}
    for path,sha in EXPECTED.items():
        if git("hash-object",path)!=sha:
            raise RuntimeError("P197_PINNED_FILE_CHANGED_"+path)
        if path in (ACTIVITY,BUILDER):data[path]=Path(path).read_text()
    modified={ACTIVITY:patch_activity(data[ACTIVITY]),
              BUILDER:patch_builder(data[BUILDER])}
    for name,content in modified.items():Path(name).write_text(content)
    if set(git("diff","--name-only").splitlines())!=set(modified):
        raise RuntimeError("P197_DIFF_SCOPE_DRIFT")
    print("P197_CI_ONLY_TWO_PINNED_P43_SOURCE_PATCHES=PASS")
    print("P197_ACTUAL_ORIGINAL_PRODUCTION_PACKAGE_CHANGED=NO")
    print("P197_P47_HOST_FALLBACK_AND_ORIGINAL_NODE=DENY")
if __name__=="__main__":
    try:main()
    except (RuntimeError,ValueError,KeyError,subprocess.CalledProcessError) as e:
        print("P197_FAIL_CLOSED",str(e),file=sys.stderr)
        sys.exit(2)
