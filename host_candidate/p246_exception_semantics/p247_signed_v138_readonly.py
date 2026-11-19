#!/usr/bin/env python3
"""P247 exact-SHA signed-v138 exception parser cross-check. Read-only."""
import argparse,hashlib,re,sys,zipfile
from pathlib import Path
from p246_exception_semantics import decode
sys.path.insert(0,"host_candidate/p209_original_p47_deny")
from p243_signed_exception_handler_cfg import handler_definitions
SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
SIZE=147341486
CORO="Lcom/dsh/android/EngineManager$start$2;"
DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
class Refused(Exception):pass
def need(ok,code):
    if not ok:raise Refused("P247_DENY_"+code)
def audit(apk):
    from androguard.core.dex import DEX
    need(apk.is_file() and not apk.is_symlink(),"FILE")
    need(apk.stat().st_size==SIZE and hashlib.sha256(apk.read_bytes()).hexdigest()==SHA,"SIGNED_SHA")
    with zipfile.ZipFile(apk) as z:
        need(z.testzip() is None,"ZIP_CRC")
        found=sorted(name for name in z.namelist()
                     if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",name))
        need(found==["classes.dex","classes2.dex"],"DEX_SET")
        dex=DEX(z.read("classes.dex"))
    methods=[method for cls in dex.get_classes() if cls.get_name()==CORO
             for method in cls.get_methods()
             if method.get_name()=="invokeSuspend" and
             "".join(method.get_descriptor().split())==DESC]
    need(len(methods)==1 and methods[0].get_code() is not None,"EXACT_START2")
    m=methods[0]
    pcs={pc for pc,_ in m.get_instructions_idx()}
    need(all(pc in pcs for pc in (0,176,182,190,194,202,214,3912)),"SIGNED_PC_ANCHORS")
    total,canonical=decode(m,dex)
    code=m.get_code()
    need(total==code.get_insns_size() and len(canonical)==code.get_tries_size()
         and len(canonical)>0,"ORIGINAL_TRY_SHAPE")
    independent=handler_definitions(code)
    tries=list(code.get_tries() or [])
    need(len(tries)==len(canonical),"ORIGINAL_TRY_COUNT")
    for item,canonical_item in zip(tries,canonical):
        start,width,(typed,catchall)=canonical_item
        need((start,width)==(item.get_start_addr(),item.get_insn_count()),
             "ORIGINAL_TRY_BOUNDS")
        targets=tuple(pc for _,pc in typed)
        if catchall is not None:targets+=(catchall,)
        need(item.get_handler_off() in independent and
             targets==independent[item.get_handler_off()],"P243_HANDLER_CROSSCHECK")
    for line in (
     "P247_SIGNED_V138_SHA_AND_DEX=PASS",
     "P247_ORIGINAL_START2_INSTRUCTION_COVERAGE=PASS",
     "P247_ORIGINAL_START2_CATCH_SEMANTICS=PASS",
     "P247_P243_INDEPENDENT_TARGET_CROSSCHECK=PASS",
     "P247_SIGNED_APK_MODIFIED=NO",
     "P247_P245_DERIVED_PARITY=NOT_ATTESTED",
     "P247_ANDROID_ART_VERIFIER=NOT_ATTESTED",
     "P247_RUNTIME_PROCESS_STATE=NOT_ATTESTED",
     "P247_V139=STRUCTURAL_BLOCKED",
     "P247_SIGNED_ORIGINAL_READONLY_AUDIT=PASS"):
        print(line)
def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original",type=Path)
    a=p.parse_args()
    try:audit(a.signed_original)
    except Exception as exc:
        value=str(exc)
        if not re.fullmatch(r"(?:P247|P246|P243)_DENY_[A-Z0-9_]{3,100}",value):
            value="P247_DENY_UNEXPECTED"
        print(value,file=sys.stderr)
        return 2
    return 0
if __name__=="__main__":raise SystemExit(main())
