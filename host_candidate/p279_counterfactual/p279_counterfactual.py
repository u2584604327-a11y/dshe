#!/usr/bin/env python3
"""P279 disposable CI-only counterfactual: reuse harmless existing DEX strings.

Never touches original/signed v138 or immutable P245 source. Only rewrites THREE
known logging literal values in the TEMPORARY P245-added helper, backed up byte
for byte, and restores before original P245 --restore. The helper remains one
original-deny-only diagnostic, not a production artifact, ART proof or policy.
"""
import argparse,hashlib,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p245_build_only_probe",
             "host_candidate/p249_dual_diff",
             "host_candidate/p246_exception_semantics"]
import p245_build_only_probe as p245
from p249_dual_diff import seal
from p246_exception_semantics import load,need

ROOT=Path(".p279tmp")
SOURCE_BACKUP=ROOT/"p245-patched-original.smali"
EDITED_DIGEST=ROOT/"p279-modified.sha256"
TAG_ALLOWLIST=("DSH","MainActivity","Android","Log")
NON_NULL="true"
NULL="false"
OLD_TAG='    const-string v1, "P245_STATE"'
OLD_YES='    const-string v2, "PROCESS_NON_NULL"'
OLD_NO='    const-string v2, "PROCESS_NULL"'

def choose_literals(existing):
    """Only unambiguous, non-sensitive, preexisting harmless string IDs."""
    if not isinstance(existing,(set,frozenset,list,tuple)):return None
    if not all(isinstance(v,str) for v in existing):return None
    names=set(existing)
    tag=next((x for x in TAG_ALLOWLIST if x in names),None)
    if tag is None or NON_NULL not in names or NULL not in names:return None
    if len({tag,NON_NULL,NULL})!=3:return None
    return (tag,NON_NULL,NULL)

def convert_helper(s,choices):
    """Return edited P245-patched source, strictly preserving all other bytes."""
    need(isinstance(s,str) and isinstance(choices,tuple) and
         len(choices)==3,"HELPER_ARGS")
    tag,yes,no=choices
    need(tag in TAG_ALLOWLIST and yes==NON_NULL and no==NULL,
         "ALLOWED_ONLY")
    need(s.count(p245.NEW)==1 and s.count(p245.OLD)==0,
         "P245_TEMP_PATCHED")
    original_helper=p245.helper(p245.captured(s))
    need(s.endswith(original_helper) and s.count(original_helper)==1,
         "P245_HELPER_SUFFIX_EXACT")
    need(original_helper.count(OLD_TAG)==2 and
         original_helper.count(OLD_YES)==1 and
         original_helper.count(OLD_NO)==1,"P245_3_LOG_STRING_SLOTS")
    new_helper=(original_helper
         .replace(OLD_TAG,'    const-string v1, "'+tag+'"')
         .replace(OLD_YES,'    const-string v2, "'+yes+'"')
         .replace(OLD_NO,'    const-string v2, "'+no+'"'))
    need(new_helper!=original_helper and new_helper.count(p245.NAME)==1,
         "P279_DIFF_BOUNDED")
    prefix=s[:-len(original_helper)]
    out=prefix+new_helper
    need(out.startswith(prefix) and len(out)!=len(s) and
         out.count(p245.NEW)==1 and out.count(p245.OLD)==0,
         "P279_EXACT_HELPER_ONLY")
    return out

def apply():
    # P249 seal before reading any original-Dex-derived data.
    seal(p245.SIGN)
    p245.scope()
    need(p245.SEAL.is_file() and not p245.SEAL.is_symlink(),
         "ORIGINAL_P245_PATCH_SEAL")
    need(not ROOT.exists(),"P279_NOT_ALREADY_ACTIVE")
    base=load(p245.BASE)
    get=getattr(base,"get_strings",None)
    need(callable(get),"BASE_POOL")
    strings=get()
    choices=choose_literals(strings)
    need(choices is not None,"SAFE_LITERAL_NOT_IN_BASE_POOL")
    orig=p245.SRC.read_bytes()
    new=convert_helper(orig.decode("utf-8"),choices).encode("utf-8")
    ROOT.mkdir(parents=True,exist_ok=False)
    SOURCE_BACKUP.write_bytes(orig)
    EDITED_DIGEST.write_text(hashlib.sha256(new).hexdigest()+"\n")
    p245.SRC.write_bytes(new)
    need(p245.SRC.read_bytes()==new and
         hashlib.sha256(SOURCE_BACKUP.read_bytes()).hexdigest()==
         hashlib.sha256(orig).hexdigest(),"P279_WRITTEN_ONLY_HELPER")
    print("P279_TEMP_BASELINE_POOL_SAFE_LITERALS=FOUND")
    print("P279_TEMP_HELPER_LOG_LITERALS_REUSED=3")
    print("P279_TEMP_HELPER_EXTRA_LITERAL_IDS=0")
    print("P279_TEMP_ORIGINAL_P245_HELPER_SOURCE=SEALED")

def restore():
    need(SOURCE_BACKUP.is_file() and EDITED_DIGEST.is_file(),
         "P279_BACKUP_REQUIRED")
    need(hashlib.sha256(p245.SRC.read_bytes()).hexdigest()==
         EDITED_DIGEST.read_text().strip(),"P279_NO_THIRD_PARTY_MUTATION")
    original=SOURCE_BACKUP.read_bytes()
    need(original.decode("utf-8").endswith(
         p245.helper(p245.captured(original.decode("utf-8")))),
         "P279_RESTORE_P245_HELPER_EXACT")
    p245.SRC.write_bytes(original)
    need(p245.SRC.read_bytes()==original,"P279_BYTE_RESTORE")
    SOURCE_BACKUP.unlink();EDITED_DIGEST.unlink();ROOT.rmdir()
    print("P279_TEMP_HELPER_RESTORED_BYTE_EXACT=PASS")

def main():
    p=argparse.ArgumentParser()
    g=p.add_mutually_exclusive_group()
    g.add_argument("--apply",action="store_true")
    g.add_argument("--restore",action="store_true")
    a=p.parse_args()
    if not a.apply and not a.restore:
        print("P279_SOURCE_ONLY=YES")
        print("P279_REAL_BASE_POOL_AND_HELPER=NOT_ATTESTED")
        print("P279_RELEASE=DENY")
        print("P279_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        if a.apply:apply()
        else:restore()
        print("P279_ONLY_CI_TEMPORARY_SOURCE=YES")
        print("P279_RELEASE=DENY")
        print("P279_V139=STRUCTURAL_BLOCKED")
        return 0
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P279_DENY_UNEXPECTED"
        print(code,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
