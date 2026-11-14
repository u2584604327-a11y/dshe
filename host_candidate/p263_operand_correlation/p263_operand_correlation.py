#!/usr/bin/env python3
"""P263 privacy-safe diagnosis of P261 structured divergence and unknowns.

No method identities, register indices, operand values or reference strings
ever printed. This does not relax the immutable P245 full static denial.
"""
import argparse,re,sys
from collections import Counter
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family",
              "host_candidate/p259_all_operands",
              "host_candidate/p261_all_method_census"]
from p246_exception_semantics import need,decode,index,load,Deny
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p257_opcode_family import encoding_candidate
from p259_all_operands import inspect_pair,operands,pair
from p261_all_method_census import census,method_observation,opaque

FIELDS=("DIVERGENT_SIZE_CHANGED","DIVERGENT_SIZE_STABLE",
        "DIVERGENT_OPCODE_UNCHANGED","DIVERGENT_OPCODE_ENCODING",
        "DIVERGENT_OPCODE_KIND",
        "DIVERGENT_REGISTER","DIVERGENT_LITERAL",
        "DIVERGENT_RESOLVED_REFERENCE","DIVERGENT_OPERAND_SHAPE",
        "DIVERGENT_MULTIPLE_TYPES",
        "UNKNOWN_PAYLOAD","UNKNOWN_INSTRUCTION_COUNT",
        "UNKNOWN_OPERAND_FORMAT","UNKNOWN_OTHER")
def changed_kind(x,y):
    """Inspect only typed, private normalized operands; never return values."""
    a,b=x[1],y[1]
    if a!=b and not encoding_candidate(a,b):return "OPERAND_SHAPE"
    aa,bb=operands(x[3],a),operands(y[3],b)
    if aa is None or bb is None:return "OPERAND_SHAPE"
    if aa==bb:return None
    if len(aa)!=len(bb):return "OPERAND_SHAPE"
    types=set()
    for v,w in zip(aa,bb):
        if v==w:continue
        if v[0]!=w[0]:types.add("OPERAND_SHAPE")
        elif v[0]=="R":types.add("REGISTER")
        elif v[0]=="L":types.add("LITERAL")
        elif v[0]=="K":types.add("RESOLVED_REFERENCE")
        else:types.add("OPERAND_SHAPE")
    need(bool(types),"NONEMPTY_DIFFERENCE")
    return next(iter(types)) if len(types)==1 else "MULTIPLE_TYPES"

def mismatch_types(a,b,da,db):
    left,right=decode(a,da),decode(b,db)
    ra,rb=instructions(a,left),instructions(b,right)
    if len(ra)!=len(rb):return set(("OPERAND_SHAPE","OPCODE_KIND"))
    found=set()
    for x,y in zip(ra,rb):
        if pair(x,y)!="STRUCTURED_DIFFER":continue
        found.add("OPCODE_UNCHANGED" if x[1]==y[1] else
                  "OPCODE_ENCODING" if encoding_candidate(x[1],y[1])
                  else "OPCODE_KIND")
        found.add(changed_kind(x,y) or "OPERAND_SHAPE")
    need(bool(found),"MISMATCH_NOT_LOCALIZED")
    return found

def diagnose(original,derived,da,db):
    baseline=census(original,derived,da,db)  # unchanged P249 set and full census
    out=Counter({x:0 for x in FIELDS})
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        la,lb=decode(a,da),decode(b,db)
        flags=method_observation(a,b,da,db,la,lb)
        if flags["OPERANDS_STRUCTURED_DIFFER"]:
            out["DIVERGENT_SIZE_CHANGED" if la[0]!=lb[0]
                else "DIVERGENT_SIZE_STABLE"]+=1
            for kind in mismatch_types(a,b,da,db):
                out["DIVERGENT_"+kind]+=1
        elif flags["OPERANDS_NOT_ATTESTED"]:
            if opaque(a) or opaque(b):
                out["UNKNOWN_PAYLOAD"]+=1
            else:
                try:
                    ra,rb=instructions(a,la),instructions(b,lb)
                    if len(ra)!=len(rb):
                        out["UNKNOWN_INSTRUCTION_COUNT"]+=1
                    elif any(pair(x,y)=="NOT_ATTESTED" for x,y in zip(ra,rb)):
                        out["UNKNOWN_OPERAND_FORMAT"]+=1
                    else:out["UNKNOWN_OTHER"]+=1
                except Deny:
                    out["UNKNOWN_OTHER"]+=1
    need(out["DIVERGENT_SIZE_CHANGED"]+out["DIVERGENT_SIZE_STABLE"]==
         baseline["OPERANDS_STRUCTURED_DIFFER"],"DIVERGENCE_SUM")
    need(sum(out[x] for x in ("UNKNOWN_PAYLOAD","UNKNOWN_INSTRUCTION_COUNT",
                              "UNKNOWN_OPERAND_FORMAT","UNKNOWN_OTHER"))==
         baseline["OPERANDS_NOT_ATTESTED"],"UNKNOWN_SUM")
    need(out["UNKNOWN_PAYLOAD"]==baseline["UNSUPPORTED_PAYLOAD_METHODS"],
         "PAYLOAD_SUM")
    return dict(counts=dict(out),original_code_methods=baseline["ORIGINAL_CODE_METHODS"],
                divergence=baseline["OPERANDS_STRUCTURED_DIFFER"],
                unknown=baseline["OPERANDS_NOT_ATTESTED"])

def emit(result):
    need(type(result) is dict and set(result)==
         {"counts","original_code_methods","divergence","unknown"},"PUBLIC_SHAPE")
    c=result["counts"]
    need(type(c) is dict and set(c)==set(FIELDS),"PUBLIC_FIELDS")
    n=result["original_code_methods"]
    need(type(n) is int and 0<n<=1000000 and
         all(type(v) is int and 0<=v<=n for v in c.values()),"PUBLIC_VALUES")
    need(c["DIVERGENT_SIZE_CHANGED"]+c["DIVERGENT_SIZE_STABLE"]==
         result["divergence"],"PUBLIC_DIVERGENCE")
    need(sum(c[k] for k in ("UNKNOWN_PAYLOAD","UNKNOWN_INSTRUCTION_COUNT",
                            "UNKNOWN_OPERAND_FORMAT","UNKNOWN_OTHER"))==
         result["unknown"],"PUBLIC_UNKNOWN")
    for key in FIELDS:print("P263_"+key+"="+str(c[key]))
    for key,value in (
       ("SCOPE","ALL_ORIGINAL_PRIMARY_METHODS"),
       ("IDENTITY_AND_OPERANDS","WITHHELD"),
       ("COMPLETE_SEMANTIC_PARITY","NOT_ATTESTED"),
       ("UNCHANGED_P245_GATE","NOT_ATTESTED"),
       ("ART_PROCESS_OWNER","NOT_ATTESTED"),
       ("RELEASE","DENY"),
       ("V139","STRUCTURAL_BLOCKED")):
        print("P263_"+key+"="+value)
    return 2

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P263_SOURCE_ONLY=YES")
        print("P263_REAL_DIVERGENCE_KIND=NOT_ATTESTED")
        print("P263_NO_APK_BUILD_INSTALL_OR_RELEASE=YES")
        print("P263_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"PINNED_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(diagnose(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P263_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
