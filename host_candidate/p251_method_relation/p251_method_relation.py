#!/usr/bin/env python3
"""P251: first-mismatch private method equality and exception ordinal audit.

Ordinal alignment is NOT proof of normal CFG, ART or legal relocation.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics","host_candidate/p249_dual_diff"]
from p246_exception_semantics import need,decode,first_difference,index,load
from p249_dual_diff import dual,seal,START,EXC_TYPES

def ordinal_edges(method,decoded):
    total,tries=decoded
    pcs=[pc//2 for pc,_ in method.get_instructions_idx()]
    need(bool(pcs) and len(set(pcs))==len(pcs),"ORDINAL_UNIQUE")
    m={pc:i for i,pc in enumerate(pcs)}
    m[total]=len(pcs)
    out=[]
    for start,width,(typed,catchall) in tries:
        need(start in m and start+width in m and m[start]<m[start+width],"ORDINAL_TRY")
        for _,target in typed:need(target in m and target!=total,"ORDINAL_TARGET")
        if catchall is not None:need(catchall in m and catchall!=total,"ORDINAL_CATCHALL")
        out.append((m[start],m[start+width],
                    tuple((kind,m[target]) for kind,target in typed),
                    None if catchall is None else m[catchall]))
    return tuple(out)

def classify(original,derived,da,db):
    baseline=dual(original,derived,da,db)
    size_key=exc_key=exc_kind=exc_methods=None
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        left,right=decode(a,da),decode(b,db)
        if size_key is None and left[0]!=right[0]:size_key=key
        diff=first_difference((left[0],left[1]),(left[0],right[1]))
        if diff!="SAME" and exc_key is None:
            need(diff in EXC_TYPES,"EXCEPTION_CLASS")
            exc_key,exc_kind,exc_methods=key,diff,(a,b,left,right)
    def group(k):
        return "NONE" if k is None else "START_COROUTINE" if k==START else "OTHER_PRIMARY"
    need((group(size_key),group(exc_key),exc_kind or "NONE")==
         (baseline["code_group"],baseline["exception_group"],baseline["exception_category"]),
         "INDEPENDENT_P249_PARITY")
    relation="NOT_APPLICABLE" if size_key is None or exc_key is None else "SAME_METHOD" if size_key==exc_key else "DIFFERENT_METHOD"
    aligned="NOT_APPLICABLE"
    if exc_kind=="TYPED_TARGET":
        a,b,left,right=exc_methods
        aligned=("ORDINALS_MATCH_ONLY" if ordinal_edges(a,left)==ordinal_edges(b,right)
                 else "ORDINALS_DIFFER")
    return dict(size_group=group(size_key),exception_group=group(exc_key),
                exception_category=exc_kind or "NONE",relation=relation,alignment=aligned,
                code_gate=baseline["code_gate"],exception_gate=baseline["exception_gate"])

def emit(x):
    need(type(x) is dict,"PUBLIC_SHAPE")
    groups={"NONE","START_COROUTINE","OTHER_PRIMARY"}
    need(x.get("size_group") in groups and x.get("exception_group") in groups,"PUBLIC_GROUP")
    need(x.get("exception_category") in EXC_TYPES|{"NONE"},"PUBLIC_CATEGORY")
    need(x.get("relation") in {"NOT_APPLICABLE","SAME_METHOD","DIFFERENT_METHOD"},"PUBLIC_RELATION")
    need(x.get("alignment") in {"NOT_APPLICABLE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"},"PUBLIC_ALIGNMENT")
    need(x.get("code_gate") in {"PARITY","DENY"} and x.get("exception_gate") in {"PARITY","DENY"},"PUBLIC_GATE")
    need((x["size_group"]=="NONE")== (x["code_gate"]=="PARITY"),"PUBLIC_CODE_CONSISTENCY")
    need((x["exception_group"]=="NONE")== (x["exception_gate"]=="PARITY"),"PUBLIC_EXC_CONSISTENCY")
    need((x["relation"]=="NOT_APPLICABLE")== (x["size_group"]=="NONE" or x["exception_group"]=="NONE"),"PUBLIC_METHOD_CONSISTENCY")
    need((x["alignment"]=="NOT_APPLICABLE")== (x["exception_category"]!="TYPED_TARGET"),"PUBLIC_TARGET_CONSISTENCY")
    for key,value in (
      ("FIRST_SIZE_GROUP",x["size_group"]),
      ("FIRST_EXCEPTION_GROUP",x["exception_group"]),
      ("FIRST_EXCEPTION_CATEGORY",x["exception_category"]),
      ("METHOD_RELATION",x["relation"]),
      ("HANDLER_ORDINAL_ALIGNMENT",x["alignment"]),
      ("CODE_GATE",x["code_gate"]),
      ("EXCEPTION_GATE",x["exception_gate"]),
      ("NORMAL_CFG_AND_OPERANDS","NOT_ATTESTED"),
      ("LEGAL_RELOCATION","NOT_ATTESTED"),
      ("FULL_P245_GATE","NOT_ATTESTED"),
      ("ART_AND_PROCESS_OWNER","NOT_ATTESTED"),
      ("V139","STRUCTURAL_BLOCKED")):
        print("P251_"+key+"="+value)
    return 2 if "DENY" in (x["code_gate"],x["exception_gate"]) else 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(v is None for v in paths):
        print("P251_SOURCE_ONLY=PASS")
        print("P251_REAL_METHOD_RELATION=NOT_ATTESTED")
        print("P251_LEGAL_RELOCATION=NOT_ATTESTED")
        print("P251_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(classify(index(da),index(db),da,db))
    except Exception as e:
        msg=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",msg):msg="P251_DENY_UNEXPECTED"
        print(msg,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
