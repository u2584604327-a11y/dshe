#!/usr/bin/env python3
"""P261 original all-method bounded DEX diff census, strictly diagnostic-only.

Inspect every ORIGINAL method. One optional pinned P245 helper is excluded by
P249 exact method-set policy. Every opaque switch/payload, missing operand,
unknown register frame or unexpected instruction classification is reported as
unattested; none may be silently counted as full parity. No private names,
offsets, operands or method descriptors are printed.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family",
              "host_candidate/p259_all_operands"]
from p246_exception_semantics import need,decode,index,load,first_difference
from p249_dual_diff import dual,seal
from p251_method_relation import ordinal_edges
from p253_cfg_ordinal import instructions,branches,UNSUPPORTED
from p257_opcode_family import encoding_candidate,frame
from p259_all_operands import pair,aggregate

COUNTS=("ORIGINAL_CODE_METHODS","CODE_SIZE_CHANGED","RAW_EXCEPTION_CHANGED",
        "EXCEPTION_ORDINAL_CHANGED","OPCODE_COUNT_CHANGED",
        "OPCODE_ENCODING_CANDIDATE_ONLY","OPCODE_OPERATION_KIND_CHANGED",
        "UNSUPPORTED_PAYLOAD_METHODS","BRANCH_SIGNATURE_CHANGED",
        "FRAME_CHANGED","FRAME_NOT_ATTESTED",
        "OPERANDS_STRUCTURED_MATCH","OPERANDS_STRUCTURED_DIFFER",
        "OPERANDS_NOT_ATTESTED")
MAX_METHODS=1000000

def opaque(method):
    """Explicitly account for every unsupported switch/payload code item."""
    for _,ins in method.get_instructions_idx():
        name=ins.get_name()
        need(isinstance(name,str),"OPCODE_NAME_TYPE")
        if name in UNSUPPORTED or name.endswith("-payload"):
            return True
    return False

def explicit_branches(rows,total):
    """Normalize GOTO encoding variants only; targets/fallthrough must match."""
    entries=branches(rows,total)
    return tuple((src,"goto" if op in ("goto","goto/16","goto/32") else op,dst,fall)
                 for src,op,dst,fall in entries)

def method_observation(a,b,da,db,la=None,lb=None):
    la=decode(a,da) if la is None else la
    lb=decode(b,db) if lb is None else lb
    result={key:0 for key in COUNTS}
    result["ORIGINAL_CODE_METHODS"]=1
    result["CODE_SIZE_CHANGED"]=int(la[0]!=lb[0])
    # P249 precedent: inspect raw exception table even when code size differs.
    raw=first_difference((la[0],la[1]),(la[0],lb[1]))
    result["RAW_EXCEPTION_CHANGED"]=int(raw!="SAME")
    result["EXCEPTION_ORDINAL_CHANGED"]=int(
        ordinal_edges(a,la)!=ordinal_edges(b,lb))
    fr=frame(a,b)
    result["FRAME_CHANGED"]=int(fr=="DIFFER")
    result["FRAME_NOT_ATTESTED"]=int(fr=="NOT_ATTESTED")
    if opaque(a) or opaque(b):
        result["UNSUPPORTED_PAYLOAD_METHODS"]=1
        result["OPERANDS_NOT_ATTESTED"]=1
        # Not comparable: opcode count, operands and switch edges NOT attested.
        return result
    old,new=instructions(a,la),instructions(b,lb)
    if len(old)!=len(new):
        result["OPCODE_COUNT_CHANGED"]=1
        result["OPERANDS_NOT_ATTESTED"]=1
        return result
    left=explicit_branches(old,la[0])
    right=explicit_branches(new,lb[0])
    result["BRANCH_SIGNATURE_CHANGED"]=int(left!=right)
    kinds=[(x[1],y[1]) for x,y in zip(old,new) if x[1]!=y[1]]
    if kinds:
        if all(encoding_candidate(x,y) for x,y in kinds):
            result["OPCODE_ENCODING_CANDIDATE_ONLY"]=1
        else:
            result["OPCODE_OPERATION_KIND_CHANGED"]=1
    all_states=[pair(x,y) for x,y in zip(old,new)]
    status=aggregate(all_states)
    need(status in {"STRUCTURED_MATCH","STRUCTURED_DIFFER","NOT_ATTESTED"},
         "OPCODE_OPERAND_STATE")
    result["OPERANDS_"+status]=1
    return result

def census(original,derived,da,db):
    # Exact P249 method set: only the pre-authorized synthetic helper is allowed.
    base=dual(original,derived,da,db)
    need(type(original) is dict and len(original)<=MAX_METHODS,"METHOD_COUNT_LIMIT")
    totals={name:0 for name in COUNTS}
    for key in sorted(original):
        a,b=original[key],derived[key]
        ca,cb=a.get_code(),b.get_code()
        need((ca is None)==(cb is None),"CODE_PRESENCE")
        if ca is None:continue
        la,lb=decode(a,da),decode(b,db)
        obs=method_observation(a,b,da,db,la,lb)
        for field in COUNTS:totals[field]+=obs[field]
    need(0<totals["ORIGINAL_CODE_METHODS"]<=MAX_METHODS,"ORIGINAL_CODE_METHODS")
    need((totals["CODE_SIZE_CHANGED"]>0)==(base["code_gate"]=="DENY"),
         "P249_SIZE_INVARIANT")
    need((totals["RAW_EXCEPTION_CHANGED"]>0)==(base["exception_gate"]=="DENY"),
         "P249_EXCEPTION_INVARIANT")
    need(totals["OPERANDS_STRUCTURED_MATCH"]+
         totals["OPERANDS_STRUCTURED_DIFFER"]+
         totals["OPERANDS_NOT_ATTESTED"]==totals["ORIGINAL_CODE_METHODS"],
         "COMPLETE_METHOD_COVERAGE")
    for field in COUNTS:need(0<=totals[field]<=totals["ORIGINAL_CODE_METHODS"],"COUNT_BOUNDS")
    return totals

def emit(counts):
    need(type(counts) is dict and set(counts)==set(COUNTS),"COUNT_SCHEMA")
    n=counts["ORIGINAL_CODE_METHODS"]
    need(type(n) is int and 0<n<=MAX_METHODS,"COUNT_N")
    need(all(type(counts[k]) is int and 0<=counts[k]<=n for k in COUNTS),"COUNT_VALUE")
    need(counts["OPERANDS_STRUCTURED_MATCH"]+
         counts["OPERANDS_STRUCTURED_DIFFER"]+
         counts["OPERANDS_NOT_ATTESTED"]==n,"ALL_METHODS_ACCOUNTED")
    for k in COUNTS:print("P261_"+k+"="+str(counts[k]))
    # A count is NOT proof of instruction semantic equivalence; every unknown
    # or difference stays visible. The unchanged original gate remains binding.
    for key,value in (
      ("SCOPE","ALL_ORIGINAL_CODE_METHODS"),
      ("UNKNOWN_SWITCH_AND_PAYLOAD","COUNTED_NOT_IGNORED"),
      ("SUPPORTED_OPERANDS","STRUCTURAL_ONLY"),
      ("COMPLETE_ART_SEMANTICS","NOT_ATTESTED"),
      ("ORIGINAL_P245_FULL_GATE","NOT_ATTESTED"),
      ("NODE_CHILD_ISOLATION_AND_P192_EGRESS","NOT_ATTESTED"),
      ("RELEASE","DENY"),
      ("V139","STRUCTURAL_BLOCKED")):
        print("P261_"+key+"="+value)
    return 2

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    args=p.parse_args()
    paths=(args.signed_original,args.base,args.candidate)
    if all(v is None for v in paths):
        print("P261_SOURCE_ONLY=YES")
        print("P261_REAL_ALL_METHOD_CENSUS=NOT_ATTESTED")
        print("P261_NO_APK_BUILD_ADB_EMULATOR_OR_RELEASE=YES")
        print("P261_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"PINNED_THREE_INPUTS")
        seal(args.signed_original)
        da,db=load(args.base),load(args.candidate)
        return emit(census(index(da),index(db),da,db))
    except Exception as exc:
        msg=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",msg):
            msg="P261_DENY_UNEXPECTED"
        print(msg,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
