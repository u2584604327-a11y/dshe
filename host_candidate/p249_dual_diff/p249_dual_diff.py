#!/usr/bin/env python3
"""P249 source-only dual-channel diagnostic; never a release/ART/running gate."""
import argparse,hashlib,re,sys,zipfile
from pathlib import Path
sys.path.insert(0,"host_candidate/p246_exception_semantics")
from p246_exception_semantics import need,decode,first_difference,index,load
SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
SIZE=147341486
OWNER="Lcom/dsh/android/EngineManager$start$2;"
START=(OWNER,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")
HELPER=(OWNER,"p245Observe$ci","("+OWNER+")V")
EXC_TYPES=frozenset({"TRY_COUNT","TRY_ORDER","TRY_SPAN","TYPED_COUNT",
    "HANDLER_ORDER","TYPE_DESCRIPTOR","TYPED_TARGET",
    "CATCHALL_PRESENCE","CATCHALL_TARGET","UNCLASSIFIED_DENY"})
GROUPS=frozenset({"NONE","START_COROUTINE","OTHER_PRIMARY"})
def group(key):
    need(type(key) is tuple and len(key)==3,"KEY_SHAPE")
    return "START_COROUTINE" if key==START else "OTHER_PRIMARY"
def dual(original,derived,odex,ddex):
    """Track both first discrepancies; no method names or offsets exposed."""
    need(type(original) is dict and type(derived) is dict,"INDEX_SHAPE")
    a,b=set(original),set(derived)
    added=b-a
    need(added in (set(),{HELPER}) and a==b-added,"METHOD_SET")
    cg,eg,ec="NONE","NONE","NONE"
    examined=0
    for key in sorted(original):
        m,n=original[key],derived[key]
        code,other=m.get_code(),n.get_code()
        need((code is None)==(other is None),"CODE_PRESENCE")
        if code is None:continue
        examined+=1
        left,right=decode(m,odex),decode(n,ddex)
        if left[0]!=right[0] and cg=="NONE":cg=group(key)
        # Decoded DEX is validated independently before dropping code_size
        # from the EXCEPTION-only comparison. Size mismatch still DENY.
        exc=first_difference((left[0],left[1]),(left[0],right[1]))
        need(exc=="SAME" or exc in EXC_TYPES,"EXCEPTION_CLASS")
        if exc!="SAME" and eg=="NONE":eg,ec=group(key),exc
    need(examined>0,"NO_CODE")
    return {
      "code_group":cg,"code_category":"CODE_SIZE" if cg!="NONE" else "NONE",
      "exception_group":eg,"exception_category":ec,
      "code_gate":"DENY" if cg!="NONE" else "PARITY",
      "exception_gate":"DENY" if eg!="NONE" else "PARITY"}
def seal(original):
    """Mandatory signed-v138 original pin for any later actual APK inputs."""
    need(original.is_file() and not original.is_symlink(),"ORIGINAL_FILE")
    need(original.stat().st_size==SIZE,"ORIGINAL_SIZE")
    h=hashlib.sha256()
    with original.open("rb") as f:
        for part in iter(lambda:f.read(1024*1024),b""):h.update(part)
    need(h.hexdigest()==SHA,"ORIGINAL_SHA256")
    with zipfile.ZipFile(original) as z:
        need(z.testzip() is None,"ORIGINAL_ZIP_CRC")
        dex=sorted(x for x in z.namelist()
            if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",x))
        need(dex==["classes.dex","classes2.dex"],"ORIGINAL_DEX_SET")
def emit(q):
    need(type(q) is dict,"RESULT_TYPE")
    need(q.get("code_group") in GROUPS and
         q.get("exception_group") in GROUPS,"GROUP_ENUM")
    need(q.get("code_category") in {"NONE","CODE_SIZE"} and
         q.get("exception_category") in EXC_TYPES|{"NONE"},"CATEGORY_ENUM")
    need(q.get("code_gate") in {"DENY","PARITY"} and
         q.get("exception_gate") in {"DENY","PARITY"},"GATE_ENUM")
    need((q["code_group"]=="NONE")== (q["code_category"]=="NONE") ==
         (q["code_gate"]=="PARITY"),"CODE_RESULT_CONSISTENCY")
    need((q["exception_group"]=="NONE")== (q["exception_category"]=="NONE") ==
         (q["exception_gate"]=="PARITY"),"EXC_RESULT_CONSISTENCY")
    for k,v in (
        ("FIRST_CODE_SIZE_GROUP",q["code_group"]),
        ("FIRST_CODE_SIZE_CATEGORY",q["code_category"]),
        ("FIRST_EXCEPTION_GROUP",q["exception_group"]),
        ("FIRST_EXCEPTION_CATEGORY",q["exception_category"]),
        ("CODE_SIZE_GATE",q["code_gate"]),
        ("EXCEPTION_GATE",q["exception_gate"]),
        ("UNCHANGED_P245_FULL_STATIC_GATE","NOT_ATTESTED"),
        ("ART_VERIFIER_RUNTIME_STATE","NOT_ATTESTED"),
        ("V139","STRUCTURAL_BLOCKED")):
        print("P249_"+k+"="+v)
    return 2 if "DENY" in (q["code_gate"],q["exception_gate"]) else 0
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in args):
        print("P249_SOURCE_ONLY_NO_APK=PASS")
        print("P249_REAL_DERIVED_EXCEPTION_DIFF=NOT_ATTESTED")
        print("P249_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in args),"THREE_PINNED_INPUTS")
        seal(a.signed_original)
        od,dd=load(a.base),load(a.candidate)
        return emit(dual(index(od),index(dd),od,dd))
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P249_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
