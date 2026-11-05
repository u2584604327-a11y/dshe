#!/usr/bin/env python3
"""P209 temporary original-P47-gate final-DENY witness, strict read-only source."""
import argparse, json, os, subprocess, sys
from pathlib import Path
REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
GATE=Path("host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java")
GATE_BLOB="44cd38245dc87b9eff960b15dc520e60a2754c2c"
BUILDER=Path("host_candidate/p43_original_service/build_embedded_emulator_apk.sh")
VERIFY=Path("host_candidate/p47_no_fallback/p47_gate.py")
VERIFY_BLOB="49f0d5d07cf7e8fa1e0323c945ddbb1eed946065"
VERIFY_OLD="        need(len(bridge_invokes)==1 and bridge_invokes[0][0]==\"invoke-static\"\n             and DENY in bridge_invokes[0][1],\n             \"BRIDGE_NOT_EXACTLY_NO_FALLBACK\")"
VERIFY_NEW="        if os.environ.get(\"P209_FINAL_DENY_ONLY\")==\"1\":\n            need(os.environ.get(\"P47_NO_HOST_FALLBACK\")==\"1\",\n                 \"P209_NO_HOST_FALLBACK_MANDATORY\")\n            instructions=[(i.get_name(),i.get_output()) for _,i in\n                 exact_bridge_methods[0].get_instructions_idx()]\n            token_count=sum(op==\"const-string\" and\n                 \"P209_P40_BRIDGE_ENTRY=OBSERVED\" in out for op,out in instructions)\n            log_sig=\"Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I\"\n            need(len(bridge_invokes)==2 and\n                 bridge_invokes[0][0]==\"invoke-static\" and\n                 log_sig in \"\".join(bridge_invokes[0][1].split()) and\n                 bridge_invokes[1][0]==\"invoke-static\" and\n                 DENY in bridge_invokes[1][1] and\n                 token_count==1 and\n                 exact_bridge_methods[0].get_code().get_registers_size()==3,\n                 \"P209_EXACT_ONE_TEST_LOG_BEFORE_STRICT_P47\")\n        else:\n            need(len(bridge_invokes)==1 and bridge_invokes[0][0]==\"invoke-static\"\n                 and DENY in bridge_invokes[0][1],\n                 \"BRIDGE_NOT_EXACTLY_NO_FALLBACK\")"
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
P208_HOOK='    python3 host_candidate/p208_original_start_coroutine/patch_ci_only.py --inject-smali "$DIR/decoded"\n'
P209_HOOK='    python3 host_candidate/p209_original_p47_deny/patch_gate_ci_only.py --inject-p40\n'
P40_SRC=Path(".p43tmp/decoded/smali/com/dsh/android/p40/P40ProcessBridge.smali")
P40_HDR=".method public static start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;\n    .registers 2\n"
P40_CALL="    invoke-static {p0}, Lcom/dsh/android/p47/P47LaunchGate;->startOrDeny(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;\n"
P40_LOG=('    const-string v0, "P209_P40"\n'
         '    const-string v1, "P209_P40_BRIDGE_ENTRY=OBSERVED"\n'
         '    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I\n')
# P209 strictly disposable original-PC3912 pre-P40 marker.
PRE_SRC=Path(".p43tmp/decoded/smali/com/dsh/android/EngineManager$start$2.smali")
PRE_JAVA="host_candidate/p209_original_p47_deny/android/com/dsh/android/p209/P209PreCallWitness.java"
P208_JAVA="host_candidate/p208_original_start_coroutine/android/com/dsh/android/p208/P208StartCoroutineWitness.java"
PRE_INVOKE="    invoke-static {}, Lcom/dsh/android/p209/P209PreCallWitness;->mark()V\n"
P40_TARGET="Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
GUARD_INVOKE="    invoke-static {}, Lcom/dsh/android/p209/P209PreCallWitness;->markFirstGuard()V\n"
GUARD_MAX_PC=3912
FALL_INVOKE="    invoke-static {}, Lcom/dsh/android/p209/P209PreCallWitness;->markFallthrough()V\n"

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
    need(s.count(P208_HOOK)==1 and P209_HOOK not in s,
         "PINNED_P208_BUILDER_HOOK")
    out=s.replace(BEFORE,AFTER,1).replace(P208_HOOK,P208_HOOK+P209_HOOK,1)
    java_line="  "+P208_JAVA+" \\\n"
    added_line="  "+PRE_JAVA+" \\\n"
    need(out.count(java_line)==1 and PRE_JAVA not in out,
         "PINNED_P208_JAVAC_LINE")
    out=out.replace(java_line,java_line+added_line,1)
    need(out.replace(added_line,"",1).
         replace(P208_HOOK+P209_HOOK,P208_HOOK,1).
         replace(AFTER,BEFORE,1)==s,"ONLY_GATE_P40_HOOK_AND_JAVA")

    return out
def patch_verifier(s):
    need(s.count(VERIFY_OLD)==1 and VERIFY_NEW not in s,
         "EXPECTED_STRICT_P47_VERIFIER")
    patched=s.replace(VERIFY_OLD,VERIFY_NEW,1)
    need(patched.replace(VERIFY_NEW,VERIFY_OLD,1)==s,
         "P47_VERIFIER_EXACT_INVERSE")
    return patched
def scope(prepared=False):
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
    need(TMP.is_file() if prepared else not TMP.exists(),
         "TEMP_GATE_STATE_DRIFT")
    expected=[str(BUILDER),str(VERIFY)] if prepared else [str(BUILDER)]
    need(git("diff","--name-only").splitlines()==expected,
         "ONLY_TEST_BUILDER_AND_PINNED_VERIFIER_CHANGED")
def prepare():
    scope()
    src=GATE.read_text()
    need(git("hash-object",str(VERIFY))==VERIFY_BLOB,
         "ORIGINAL_P47_VERIFIER_SOURCE_PIN")
    old_verifier=VERIFY.read_text()
    new_verifier=patch_verifier(old_verifier)
    TMP.parent.mkdir(parents=True,exist_ok=True)
    TMP.write_text(patch_gate(src))
    BUILDER.write_text(patch_builder(BUILDER.read_text()))
    VERIFY.write_text(new_verifier)
    need(VERIFY.read_text().replace(VERIFY_NEW,VERIFY_OLD,1)==old_verifier,
         "ONLY_PINNED_TEST_LOG_ALLOWLIST_ADDED")
    need(GATE.read_text()==src and
         TMP.read_text().replace(ENTER,"",1).replace(STACK,"",1).
             replace(FINAL,"",1)==src,"REAL_GATE_NOT_EDITED")
    need(git("diff","--name-only").splitlines()==[str(BUILDER),str(VERIFY)],
         "WORKTREE_SCOPE")
    print("P209_TEMP_P47_VERIFIER_STRICT_LOG_ALLOWLIST=PASS")
    print("P209_SHA_PINNED_REAL_P47_SOURCE_UNCHANGED=PASS")
    print("P209_ONLY_DISPOSABLE_GATE_THREE_FIXED_LOG_MARKERS=PASS")
    print("P209_TEMP_BUILDER_SOURCE_SWITCH_ONLY=PASS")
def patch_p40(s):
    need(s.count(P40_HDR)==1 and s.count(P40_CALL)==1 and
         P40_LOG not in s,"EXACT_ORIGINAL_P40_DENY_SHAPE")
    new_hdr=P40_HDR.replace(".registers 2",".registers 3")
    out=s.replace(P40_HDR,new_hdr,1).replace(P40_CALL,P40_LOG+P40_CALL,1)
    need(out.replace(P40_LOG,"",1).replace(new_hdr,P40_HDR,1)==s,
         "P40_EXACT_REGISTER_AND_LOG_INVERSE")
    need("Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;" not in out,
         "P40_NO_HOST_SPAWN")
    return out
def inject_precall(s, expected_guard_op="if-ne"):
    import re
    need(PRE_INVOKE.strip() not in s and GUARD_INVOKE.strip() not in s and
         FALL_INVOKE.strip() not in s,"PRECALL_OR_GUARD_OR_FALL_ALREADY_MARKED")
    import sys
    sys.path.insert(0,"host_candidate/p208_original_start_coroutine")
    import patch_ci_only as p208
    a,b,body=p208.find_method(s)
    need(body.count(p208.INSERT.strip())==1,"P208_FIRST_MARKER_REQUIRED")
    rows=body.splitlines(keepends=True)
    calls=[i for i,line in enumerate(rows) if
           P40_TARGET in line and line.lstrip().startswith("invoke-static ")]
    need(len(calls)==1,"EXACT_ONE_ORIGINAL_PC3912_P40_CALL")
    call_idx=calls[0]
    expected=(r"^[ \t]+invoke-static[ \t]+\{[vp][0-9]+\},[ \t]*"+
              re.escape(P40_TARGET)+r"[ \t]*\n?$")
    need(re.fullmatch(expected,rows[call_idx]) is not None,
         "ORIGINAL_PC3912_P40_CALL_SHAPE")
    at=sum(map(len,rows[:call_idx]))
    conds=[(i,line) for i,line in enumerate(rows) if
           re.match(r"^[ \t]+if-[a-z0-9/-]+[ \t]+",line)]
    need(conds and re.match(r"^[ \t]+(if-[a-z0-9/-]+)[ \t]+",conds[0][1]).group(1)
         ==expected_guard_op,"SIGNED_FIRST_GUARD_OPCODE_AND_ORDER")
    cond_idx=conds[0][0]
    guard_at=sum(map(len,rows[:cond_idx]))
    after_cond=guard_at+len(rows[cond_idx])
    need(body.index(p208.INSERT)<guard_at<after_cond<=at,
         "ENTRY_FIRST_COND_FALLTHROUGH_PRE_PC3912_ORDER")
    newbody=(body[:guard_at]+GUARD_INVOKE+
             body[guard_at:after_cond]+FALL_INVOKE+
             body[after_cond:at]+PRE_INVOKE+body[at:])
    new=s[:a]+newbody+s[b:]
    need(new.replace(GUARD_INVOKE,"",1).replace(FALL_INVOKE,"",1).
         replace(PRE_INVOKE,"",1)==s and
         all(new.count(marker.strip())==1
             for marker in (GUARD_INVOKE,FALL_INVOKE,PRE_INVOKE)),
         "EXACT_THREE_REVERSIBLE_CI_MARKERS")
    return new
def inject_p40():
    import hashlib
    scope(prepared=True)
    root=Path(".p43tmp/decoded")
    need(root.is_dir() and not root.is_symlink() and not P40_SRC.is_symlink(),
         "ONLY_DISPOSABLE_DECODED_P40")
    signed=Path(".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
    need(signed.is_file() and hashlib.sha256(signed.read_bytes()).hexdigest()==
         "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5",
         "EXACT_SIGNED_ORIGINAL_V138_SHA")
    # Signed-v138 first original conditional is fixed PC38 if-ne.
    import zipfile
    from androguard.core.dex import DEX
    with zipfile.ZipFile(signed) as z:
        original_dex=DEX(z.read("classes.dex"))
    methods=[m for c in original_dex.get_classes()
        if c.get_name()=="Lcom/dsh/android/EngineManager$start$2;"
        for m in c.get_methods() if m.get_name()=="invokeSuspend" and
        "".join(m.get_descriptor().split())=="(Ljava/lang/Object;)Ljava/lang/Object;"]
    need(len(methods)==1,"SIGNED_ORIGINAL_START2_UNIQUE")
    conds=[(pc,ins.get_name()) for pc,ins in methods[0].get_instructions_idx()
           if ins.get_name().startswith("if-")]
    need(conds and conds[0][0]==26 and conds[0][1]=="if-eqz",
         "SIGNED_FIRST_GUARD_PC26_IF_EQZ")
    original_first_pc,original_first_op=conds[0]
    signed_first_instruction=next(ins for pc,ins in methods[0].get_instructions_idx()
                                  if pc==original_first_pc)
    need(original_first_pc+signed_first_instruction.get_length()==30 and
         original_first_pc+2*signed_first_instruction.get_ref_off()==176,
         "SIGNED_PC26_EXACT_FALLTHROUGH_PC30_TAKEN_PC176")
    print("P209_SIGNED_ORIGINAL_FIRST_GUARD_PC="+str(original_first_pc))
    print("P209_SIGNED_ORIGINAL_FIRST_GUARD_OP="+original_first_op)
    need(P40_SRC.is_file(),"P40_DENY_BRIDGE_REQUIRED")
    s=P40_SRC.read_text()
    modified=patch_p40(s)
    P40_SRC.write_text(modified)
    need(P40_SRC.read_text().replace(P40_LOG,"",1).
         replace(P40_HDR.replace(".registers 2",".registers 3"),P40_HDR,1)==s,
         "ONLY_TEST_P40_LOGGING_DIFFERENCE")
    need(PRE_SRC.is_file() and not PRE_SRC.is_symlink(),"PINNED_START2_SMALI_ONLY")
    original=PRE_SRC.read_text()
    PRE_SRC.write_text(inject_precall(original,original_first_op))
    need(PRE_SRC.read_text().replace(GUARD_INVOKE,"",1).replace(FALL_INVOKE,"",1).replace(PRE_INVOKE,"",1)==original,
         "PRECALL_SOURCE_EXACT_INVERSE")
    print("P209_ONLY_TEST_ORIGINAL_FIRST_GUARD_MARKER=PASS")
    print("P209_PC26_FALLTHROUGH_PC30_ONLY_REVERSIBLE_MARKER=PASS")
    print("P209_ONLY_TEST_PRE_PC3912_MARKER=PASS")
    print("P209_ONLY_TEMP_P40_ONE_LOG_AND_NO_HOST_SPAWN=PASS")
def main():
    a=argparse.ArgumentParser()
    actions=a.add_mutually_exclusive_group(required=True)
    actions.add_argument("--prepare",action="store_true")
    actions.add_argument("--inject-p40",action="store_true")
    args=a.parse_args()
    try:
        if args.prepare:prepare()
        else:inject_p40()
    except Deny as e:print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:print("P209_UNEXPECTED_TEST_PREPARE_ERROR",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
