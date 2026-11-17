#!/usr/bin/env python3
"""P299: fail-closed categorical root cause for P298 unavailable pool refs.

Only original P263/P298 unknown-method set; no private values, DEX indices,
method IDs, offsets, type strings, field names, bytes or hashes are logged.
Resolves whether the *first/only* P298 unreadable other-pool case is an index
lookup failure vs malformed returned field/type/string and on which side.
Multiple simultaneous failures remain MULTIPLE_OR_UNVERIFIED. Diagnostics
never repair P245 or authorize APK release, ART, switch payload or P192.
"""
import argparse,re,sys
from collections import Counter
from pathlib import Path
sys.path[:0]=[
 "host_candidate/p246_exception_semantics",
 "host_candidate/p249_dual_diff",
 "host_candidate/p251_method_relation",
 "host_candidate/p253_cfg_ordinal",
 "host_candidate/p255_branch_separation",
 "host_candidate/p257_opcode_family",
 "host_candidate/p259_all_operands",
 "host_candidate/p261_all_method_census",
 "host_candidate/p263_operand_correlation",
 "host_candidate/p265_operand_shape",
 "host_candidate/p267_invoke_words",
 "host_candidate/p269_method_pool",
 "host_candidate/p295_raw_unknowns",
 "host_candidate/p296_instruction_shape",
 "host_candidate/p297_raw_invoke_pool",
 "host_candidate/p298_other_pool_refs",
]
from p246_exception_semantics import load,need,index
from p249_dual_diff import seal
from p261_all_method_census import method_observation
from p263_operand_correlation import diagnose
from p295_raw_unknowns import instruction_bytes
from p298_other_pool_refs import REF_SPEC,pool_value,valid_type,category as p298_category

KINDS=(
 "STRING_LOOKUP_FAILED","STRING_VALUE_INVALID",
 "TYPE_LOOKUP_FAILED","TYPE_DESCRIPTOR_INVALID",
 "FIELD_LOOKUP_FAILED","FIELD_TUPLE_INVALID",
 "FIELD_DESCRIPTOR_INVALID",
 "RAW_OR_LAYOUT_UNVERIFIED",
 "MULTIPLE_OR_UNVERIFIED",
)
SIDES=("BASE_ONLY","CANDIDATE_ONLY","BOTH","UNVERIFIED")
LIMIT=1000000

def reason_for_pool(dex,kind,idx):
    """Independent shape audit; never render the resolved value to stdout."""
    try:
        if kind=="STRING":
            x=dex.get_cm_string(idx)
            return None if isinstance(x,str) and len(x)<=8192 else "STRING_VALUE_INVALID"
        if kind=="TYPE":
            x=dex.get_cm_type(idx)
            return None if valid_type(x) else "TYPE_DESCRIPTOR_INVALID"
        if kind=="FIELD":
            x=dex.get_cm_field(idx)
            if not isinstance(x,(tuple,list)) or len(x)!=3:return "FIELD_TUPLE_INVALID"
            owner,typ,name=x
            if (not isinstance(owner,str) or re.fullmatch(r"L[^;()\\s]+;",owner) is None
                or not valid_type(typ) or not isinstance(name,str) or not (0<len(name)<=8192)
                or re.search(r"[()\\s]",name)):
                return "FIELD_DESCRIPTOR_INVALID"
            return None
    except Exception:
        return kind+"_LOOKUP_FAILED"
    return "MULTIPLE_OR_UNVERIFIED"

def defects(method,dex):
    """Collect all failures by category, never stop at first unknown."""
    if instruction_bytes(method) is None:return frozenset({"RAW_OR_LAYOUT_UNVERIFIED"})
    try:
        out=set()
        for _,inst in method.get_instructions_idx():
            data=inst.get_raw()
            if type(data) is not bytes or len(data)<2:return frozenset({"RAW_OR_LAYOUT_UNVERIFIED"})
            spec=REF_SPEC.get(data[0])
            if spec is None:continue
            kind,width,idxsize=spec
            if len(data)!=width:
                out.add("RAW_OR_LAYOUT_UNVERIFIED")
                continue
            idx=int.from_bytes(data[2:2+idxsize],"little")
            if pool_value(dex,kind,idx) is None:
                out.add(reason_for_pool(dex,kind,idx) or "MULTIPLE_OR_UNVERIFIED")
        return frozenset(out)
    except Exception:
        return frozenset({"RAW_OR_LAYOUT_UNVERIFIED"})

def classify(a,b,da,db):
    if p298_category(a,b,da,db)!="OTHER_REFERENCE_POOL_UNAVAILABLE":
        return None
    left,right=defects(a,da),defects(b,db)
    problems=left|right
    if not problems or len(problems)!=1:
        cause="MULTIPLE_OR_UNVERIFIED"
    else:
        cause=next(iter(problems))
    if cause not in KINDS:cause="MULTIPLE_OR_UNVERIFIED"
    side=("BOTH" if left and right else
          "BASE_ONLY" if left else
          "CANDIDATE_ONLY" if right else "UNVERIFIED")
    return cause,side

def audit(original,candidate,da,db):
    prior=diagnose(original,candidate,da,db)
    n=prior["unknown"]
    counts=Counter({k:0 for k in KINDS})
    sides=Counter({k:0 for k in SIDES})
    inspected=0
    for key in sorted(original):
        a,b=original[key],candidate[key]
        if a.get_code() is None:continue
        if method_observation(a,b,da,db)["OPERANDS_NOT_ATTESTED"]:
            verdict=classify(a,b,da,db)
            if verdict is None:continue
            cause,side=verdict
            need(cause in KINDS and side in SIDES,"P299_CATEGORY")
            counts[cause]+=1;sides[side]+=1;inspected+=1
    need(inspected<=n and sum(counts.values())==inspected
         and sum(sides.values())==inspected,"P299_RECONCILE")
    return {"unknown":n,"unavailable":inspected,
            "causes":dict(counts),"sides":dict(sides)}

def emit(q):
    need(type(q) is dict and set(q)=={"unknown","unavailable","causes","sides"},
         "P299_RESULT")
    n,k=q["unknown"],q["unavailable"]
    a,b=q["causes"],q["sides"]
    need(type(n) is int and type(k) is int and 0<=k<=n<=LIMIT,"P299_BOUNDS")
    need(type(a) is dict and set(a)==set(KINDS)
         and type(b) is dict and set(b)==set(SIDES),"P299_SCHEMA")
    need(all(type(x) is int and 0<=x<=k for x in list(a.values())+list(b.values()))
         and sum(a.values())==k and sum(b.values())==k,"P299_SUM")
    print("P299_UNKNOWN_METHODS="+str(n))
    print("P299_OTHER_POOL_UNAVAILABLE="+str(k))
    for name in KINDS:print("P299_CAUSE_"+name+"="+str(a[name]))
    for name in SIDES:print("P299_SIDE_"+name+"="+str(b[name]))
    print("P299_LOOKUP_FAILURE_IS_NOT_A_TARGET_MISMATCH=YES")
    print("P299_ORIGINAL_P245_GATE=UNMODIFIED")
    print("P299_SWITCH_REGISTER_ART_P192_B3_B4=NOT_ATTESTED")
    print("P299_PRIVATE_METHOD_REFS_INDICES_PCS=WITHHELD")
    print("P299_RELEASE=DENY")
    print("P299_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for x in ("signed-original","base","candidate"):p.add_argument("--"+x,type=Path)
    x=p.parse_args();args=(x.signed_original,x.base,x.candidate)
    if all(a is None for a in args):
        print("P299_SOURCE_ONLY=YES")
        print("P299_REAL_ROOT_CAUSE=NOT_ATTESTED")
        print("P299_RELEASE=DENY")
        return 0
    try:
        need(all(a is not None for a in args),"P299_PINNED_THREE_APKS")
        seal(x.signed_original)
        da,db=load(x.base),load(x.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P299_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
