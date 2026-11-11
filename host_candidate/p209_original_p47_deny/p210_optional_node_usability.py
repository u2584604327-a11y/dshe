#!/usr/bin/env python3
"""P210 OPTIONAL CI-only Node usability deny-candidate, never for user release.

Creates a temporary smali candidate with a SAME-WIDTH, ONE-CALL substitution.
The existing P209 Android35 APK is NEVER changed. Candidate unsigned APK is
verified as static-only and must NEVER be installed or executed. All original
branch targets, other method instructions and try/handler tables are compared.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import SIGNED_SHA,BOOT,need,Denied
from audit_signed_node_usability_start import original_method, direct_start_rows

REPO="u2584604327-a11y/dshe"
BRANCH="dsh/p96-original-engine-stream-owner-narrow-20261030"
SOURCE=Path(".p43tmp/decoded/smali/com/dsh/android/termux/TermuxBootstrap.smali")
ORIGINAL_APK=Path(".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
BASE_APK=Path(".p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk")
GATE_SOURCE=Path("host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java")
GATE_SHA="44cd38245dc87b9eff960b15dc520e60a2754c2c"
METHOD=re.compile(r"(?m)^\.method[^\n]*\bnodeIsUsable\([^\n]*$")
OLD_REF="Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
NEW_REF="Lcom/dsh/android/p47/P47LaunchGate;->startOrDeny(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
OLD_LINE=re.compile(r"(?m)^([ \t]*)invoke-virtual ([{][vp][0-9]+[}]), "+re.escape(OLD_REF)+r"[ \t]*$")
NEW_LINE=re.compile(r"(?m)^([ \t]*)invoke-static ([{][vp][0-9]+[}]), "+re.escape(NEW_REF)+r"[ \t]*$")

def scope():
    need(os.environ.get("GITHUB_ACTIONS")=="true" and
         os.environ.get("GITHUB_REPOSITORY")==REPO and
         os.environ.get("GITHUB_EVENT_NAME")=="pull_request",
         "CI_PR_ONLY")
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr=event.get("pull_request") or {}
    head=pr.get("head") or {}
    need(pr.get("number")==80 and head.get("ref")==BRANCH and
         (head.get("repo") or {}).get("full_name")==REPO,
         "SINGLE_EXISTING_PR_BRANCH")
    for name,wanted in (("P47_NO_HOST_FALLBACK","1"),
                        ("P181_THREE_ORIGINAL_START_DENY","1"),
                        ("P49_NODE_STAGE","0"),
                        ("P51_SIDE_BY_SIDE","0"),
                        ("P208_CI_METHOD_ENTRY_ONLY","1"),
                        ("P209_FINAL_DENY_ONLY","1"),
                        ("P74_FIXTURE_ENGINE_BRIDGE","0"),
                        ("P75_RENDEZVOUS_FIXTURE","0")):
        need(os.environ.get(name)==wanted,"FLAG_"+name)
    need(ORIGINAL_APK.is_file() and
         hashlib.sha256(ORIGINAL_APK.read_bytes()).hexdigest()==SIGNED_SHA,
         "SIGNED_SOURCE_SHA")
    gate_bytes=GATE_SOURCE.read_bytes() if GATE_SOURCE.is_file() else b""
    # Repository seal is Git's blob SHA1 (header + content), not raw SHA1.
    gate_blob=(b"blob "+str(len(gate_bytes)).encode()+b"\\x00"+gate_bytes)
    need(bool(gate_bytes) and hashlib.sha1(gate_blob).hexdigest()==GATE_SHA,
         "UNCHANGED_P47_GATE_SOURCE")
    need(SOURCE.is_file() and not SOURCE.is_symlink() and
         SOURCE.parent.resolve()==
         (Path.cwd()/".p43tmp/decoded/smali/com/dsh/android/termux").resolve(),
         "DISPOSABLE_SMALI_PATH")
    need(BASE_APK.is_file() and not BASE_APK.is_symlink(),
         "PREBUILT_P209_BASE_REQUIRED")

def isolate_method(s):
    matches=list(METHOD.finditer(s))
    need(len(matches)==1,"EXACT_METHOD_NAME_ONCE")
    start=matches[0].start()
    end=s.find(".end method",matches[0].end())
    need(end>start and end-start<36000,"METHOD_BOUND")
    need(s.find("\n.method",matches[0].end(),end)<0,"METHOD_NOT_NESTED")
    end+=len(".end method")
    return start,end,s[start:end]

def alter_text(s,reverse=False):
    a,b,body=isolate_method(s)
    src,dst=(NEW_LINE,OLD_LINE) if reverse else (OLD_LINE,NEW_LINE)
    need(len(src.findall(body))==1 and len(dst.findall(body))==0,
         "EXACT_ONE_ORIGINAL_SITE_IN_METHOD")
    changed=src.sub(lambda m:m.group(1)+
            ("invoke-virtual" if reverse else "invoke-static")+" "+
            m.group(2)+", "+(OLD_REF if reverse else NEW_REF),
            body,count=1)
    out=s[:a]+changed+s[b:]
    need(out[:a]==s[:a] and out[a+len(changed):]==s[b:],
         "ONLY_SELECTED_METHOD_CHANGED")
    need(alter_inverse_preview(out,reverse)==s,"EXACT_INVERSE_ORIGINAL")
    return out

def alter_inverse_preview(s,reverse):
    a,b,body=isolate_method(s)
    src=OLD_LINE if reverse else NEW_LINE
    need(len(src.findall(body))==1,"INVERSE_ONE_SITE")
    changed=src.sub(lambda m:m.group(1)+
           ("invoke-static" if reverse else "invoke-virtual")+" "+
           m.group(2)+", "+(NEW_REF if reverse else OLD_REF),body,count=1)
    return s[:a]+changed+s[b:]

def patch(reverse=False):
    scope()
    old=SOURCE.read_text(encoding="utf-8")
    revised=alter_text(old,reverse)
    SOURCE.write_text(revised,encoding="utf-8")
    need(SOURCE.read_text(encoding="utf-8")==revised,"WRITE_PARITY")
    print("P210_CANDIDATE_ONLY_SMALI_"+("RESTORED" if reverse else "PATCHED")+"=PASS")
    print("P210_SIGNED_ORIGINAL_APK_UNTOUCHED=YES")
    print("P210_CANDIDATE_MUST_NOT_INSTALL=YES")

def load_dex(apk):
    from androguard.core.dex import DEX
    with zipfile.ZipFile(apk) as z:
        need(z.testzip() is None and "classes.dex" in z.namelist(),
             "DEX_ARCHIVE_CRC")
        return DEX(z.read("classes.dex"))

def method_index(dex):
    entries={}
    for cls in dex.get_classes():
        name=cls.get_name()
        for m in cls.get_methods():
            key=(name,m.get_name(),"".join(m.get_descriptor().split()))
            need(key not in entries,"DUPLICATE_ORIGINAL_METHOD")
            entries[key]=m
    return entries

def instructions(m):
    if m.get_code() is None:return None
    return [(pc,ins.get_name(),ins.get_length(),ins.get_output())
            for pc,ins in m.get_instructions_idx()]

def exception_structure(m):
    code=m.get_code()
    if code is None:return None
    tries=tuple((t.get_start_addr(),t.get_insn_count(),t.get_handler_off())
                for t in (code.get_tries() or []))
    holders=code.get_handlers()
    handlers=[]
    for h in holders.get_list() if holders else []:
        handlers.append((h.get_off(),h.get_size(),
                         tuple((v.get_type_idx(),v.get_addr())
                               for v in (h.get_handlers() or [])),
                         h.get_catch_all_addr() if h.get_size()<=0 else None))
    return tries,tuple(handlers)

def validate_comparison(base_index,candidate_index):
    need(set(base_index)==set(candidate_index),"ALL_PRIMARY_METHOD_KEYS_EXACT")
    only=(BOOT,"nodeIsUsable",
          next((desc for owner,name,desc in base_index
                if owner==BOOT and name=="nodeIsUsable"),None))
    need(only[2] is not None and only in candidate_index,"UNIQUE_TARGET_METHOD")
    changed=[]
    for key,bm in base_index.items():
        cm=candidate_index[key]
        need((bm.get_code() is None)==(cm.get_code() is None),
             "METHOD_CODE_PRESENCE_DRIFT")
        if bm.get_code() is None:continue
        need(bm.get_code().get_registers_size()==
             cm.get_code().get_registers_size(),"REGISTER_COUNT_DRIFT")
        need(bm.get_code().get_ins_size()==
             cm.get_code().get_ins_size(),"PARAMETER_COUNT_DRIFT")
        need(bm.get_code().get_outs_size()==
             cm.get_code().get_outs_size(),"OUT_PARAMETER_DRIFT")
        need(exception_structure(bm)==exception_structure(cm),
             "ORIGINAL_TRY_HANDLER_DRIFT")
        b,c=instructions(bm),instructions(cm)
        need(len(b)==len(c),"ORIGINAL_INSTRUCTION_COUNT_DRIFT")
        diffs=[(left,right) for left,right in zip(b,c) if left!=right]
        if key==only:
            need(len(diffs)==1,"EXACT_ONE_METHOD_DIFF")
            (l,r)=diffs[0]
            need(l[0]==r[0]==232 and l[2]==r[2]==6 and
                 l[1]=="invoke-virtual" and r[1]=="invoke-static" and
                 OLD_REF in l[3] and NEW_REF in r[3] and
                 l[3].split(", ",1)[0]==r[3].split(", ",1)[0],
                 "PC232_EQUALWIDTH_TYPED_TARGET_ONLY")
            need([i[:3] for i in b]==
                 [(i[0],("invoke-virtual" if i[0]==232 else i[1]),i[2])
                  for i in c],"PC_AND_OPCODE_PARITY")
            changed.append(key)
        else:
            need(not diffs,"OTHER_ORIGINAL_METHOD_DRIFT")
    need(changed==[only],"EXACT_ONE_METHOD_MODIFIED")
    return len(base_index)

def verify(candidate):
    scope()
    src=SOURCE.read_text(encoding="utf-8")
    a,b,body=isolate_method(src)
    need(len(OLD_LINE.findall(body))==1 and
         len(NEW_LINE.findall(body))==0,
         "SMALI_ALREADY_RESTORED")
    base=load_dex(BASE_APK)
    cand=load_dex(candidate)
    count=validate_comparison(method_index(base),method_index(cand))
    # Confirm original signed node method has the same original PC232 site.
    orig=load_dex(ORIGINAL_APK)
    signed=original_method(orig,BOOT,"nodeIsUsable")
    bc=original_method(base,BOOT,"nodeIsUsable")
    need(instructions(signed)==instructions(bc),"BASE_ORIGINAL_UNCHANGED_METHOD")
    need(direct_start_rows(list(signed.get_instructions_idx()))==
         [(232,"invoke-virtual",6)],"SIGNED_EXACT_ONE_PC232")
    # The candidate APK may be unsigned and have no valid AXML: never install.
    print("P210_CANDIDATE_ALL_PRIMARY_METHOD_KEY_COUNT="+str(count))
    print("P210_CANDIDATE_ALL_OTHER_METHOD_INSTRUCTIONS_UNCHANGED=PASS")
    print("P210_CANDIDATE_TARGET_PC232_INVOKE_VIRTUAL_TO_STATIC=PASS")
    print("P210_CANDIDATE_INVOKE_WIDTH_BYTES=6")
    print("P210_CANDIDATE_TRY_HANDLERS_ALL_PRIMARY_METHODS_EXACT=PASS")
    print("P210_CANDIDATE_P47_TARGET=startOrDeny_TYPED_DENY_ONLY")
    print("P210_CANDIDATE_SIGNED_ORIGINAL_SHA_PIN=PASS")
    print("P210_CANDIDATE_ORIGINAL_APK_MODIFIED=NO")
    print("P210_CANDIDATE_ANDROID_EMULATOR_EXECUTED=NO")
    print("P210_CANDIDATE_PHONE_OR_USER_ACCOUNTS_TOUCHED=NO")
    print("P210_CANDIDATE_P47_RUNTIME_OBSERVED=NOT_ATTESTED")
    print("P210_CANDIDATE_PRODUCTION_RELEASE=STRUCTURAL_BLOCKED")
    print("P210_CANDIDATE_STATIC_PARITY_AUDIT=PASS")

def main():
    parser=argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--patch",action="store_true")
    modes.add_argument("--restore",action="store_true")
    modes.add_argument("--verify",metavar="CANDIDATE_APK")
    args=parser.parse_args()
    try:
        if args.patch:patch()
        elif args.restore:patch(True)
        else:verify(Path(args.verify))
    except Denied as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P210_CANDIDATE_DENY_UNEXPECTED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
