#!/usr/bin/env python3
"""P289 independent strict raw 35c Log.i comparator for P245 repair review.

Not a release gate and never an authority to edit P245. The proposed
replacement accepts only an actual two-register invoke-static with a DEX
method_id of Log.i(String,String):int. Requires original first four P245
helper predicates, unchanged original method set and all 11 independent P285
shadow invariants; leaves original P245's own DENY intact. Rejects any raw
opcode/word/register/ref, noncanonical type, frame, catch or branch anomaly.
Never prints original/private DEX details.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=[
 "host_candidate/p246_exception_semantics",
 "host_candidate/p249_dual_diff",
 "host_candidate/p267_invoke_words",
 "host_candidate/p269_method_pool",
 "host_candidate/p281_helper_predicates",
 "host_candidate/p283_descriptor_normalization",
 "host_candidate/p285_shadow_verifier",
 "host_candidate/p287_gate_delta",
]
from p246_exception_semantics import load,need,index
from p249_dual_diff import seal
from p281_helper_predicates import p245_checks,PREDICATES,OWNER,NAME,DESC
from p283_descriptor_normalization import canonical_args,canonical_return
from p285_shadow_verifier import audit as shadow_audit,FACTORS
from p287_gate_delta import audit as delta_audit,CHECKS

CHECKS289=("ORIGINAL_FOUR_HELPER_CONDITIONS","P285_ELEVEN_INVARIANTS",
           "RAW_LOG_35C_FORMAT","RAW_LOG_35C_REGISTERS",
           "RAW_LOG_DEX_OWNER","RAW_LOG_DEX_METHOD","RAW_LOG_DEX_ARGS",
           "RAW_LOG_DEX_RETURN","P287_ALL_SEVEN_REVIEW_ITEMS")
STATUS=("PASS","FAIL","UNVERIFIED")
DECISIONS=("STRICT_REPLACEMENT_PROPOSAL_ONLY","DENY")

def raw_log_target(row,dex):
    """Independent raw DEX 35c decode; no display-string or summary trust."""
    out={x:"UNVERIFIED" for x in CHECKS289[2:8]}
    if (not isinstance(row,(tuple,list)) or len(row)!=5 or
        row[1]!="invoke-static"):
        out["RAW_LOG_35C_FORMAT"]="FAIL"
        return out
    try: data=row[3].get_raw()
    except Exception:return out
    if not isinstance(data,(bytes,bytearray)) or len(data)!=6:return out
    if data[0]!=0x71 or data[1]!=0x20 or data[5]!=0x00:
        out["RAW_LOG_35C_FORMAT"]="FAIL";return out
    out["RAW_LOG_35C_FORMAT"]="PASS"
    if data[4]!=0x21:
        out["RAW_LOG_35C_REGISTERS"]="FAIL";return out
    out["RAW_LOG_35C_REGISTERS"]="PASS"
    ref_idx=data[2]|(data[3]<<8)
    try: item=dex.get_cm_method(ref_idx)
    except Exception:return out
    if (not isinstance(item,(list,tuple)) or len(item)!=3 or
        not isinstance(item[2],(list,tuple)) or len(item[2])!=2 or
        any(not isinstance(x,str) for x in (item[0],item[1],item[2][0],item[2][1]))):
        return out
    owner,name,(args,ret)=item
    out["RAW_LOG_DEX_OWNER"]="PASS" if owner=="Landroid/util/Log;" else "FAIL"
    out["RAW_LOG_DEX_METHOD"]="PASS" if name=="i" else "FAIL"
    types=canonical_args(args);returned=canonical_return(ret)
    out["RAW_LOG_DEX_ARGS"]=(
        "UNVERIFIED" if types is None else
        "PASS" if types=="(Ljava/lang/String;Ljava/lang/String;)" else "FAIL")
    out["RAW_LOG_DEX_RETURN"]=(
        "UNVERIFIED" if returned is None else
        "PASS" if returned=="I" else "FAIL")
    return out

def judge(base,candidate):
    result={key:"UNVERIFIED" for key in CHECKS289}
    original=index(base);derived=index(candidate)
    key=(OWNER,NAME,DESC)
    if set(derived)-set(original)!={key} or set(original)!=set(derived)-{key}:
        result["ORIGINAL_FOUR_HELPER_CONDITIONS"]="FAIL"
        return result
    method=derived[key]
    observed=p245_checks(method)
    if observed is None:return result
    result["ORIGINAL_FOUR_HELPER_CONDITIONS"]=(
       "PASS" if all(observed["predicates"][x] for x in PREDICATES[:4]) else "FAIL")
    rows=observed["rows"]
    if len(rows)!=14:return result
    result.update(raw_log_target(rows[10],candidate))
    # Never trust an externally supplied P285 or P287 aggregate. Compute from
    # actual baseline/candidate each time (including original code method set).
    shadow=shadow_audit(base,candidate)
    if type(shadow) is dict and set(shadow)==set(FACTORS):
        result["P285_ELEVEN_INVARIANTS"]=(
            "PASS" if all(x=="PASS" for x in shadow.values()) else
            "FAIL" if any(x=="FAIL" for x in shadow.values()) else "UNVERIFIED")
    delta,verdict=delta_audit(base,candidate)
    if type(delta) is dict and set(delta)==set(CHECKS):
        result["P287_ALL_SEVEN_REVIEW_ITEMS"]=(
            "PASS" if all(x=="PASS" for x in delta.values()) and
                verdict=="SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE" else
            "FAIL" if any(x=="FAIL" for x in delta.values()) or
                verdict=="DENY_DIFFERENT_OR_UNVERIFIED" else "UNVERIFIED")
    return result

def emit(q):
    need(type(q) is dict and set(q)==set(CHECKS289) and
         all(x in STATUS for x in q.values()),"P289_PUBLIC_SCHEMA")
    decision=("STRICT_REPLACEMENT_PROPOSAL_ONLY"
              if all(x=="PASS" for x in q.values()) else "DENY")
    need(decision in DECISIONS,"P289_DECISION_ENUM")
    for k in CHECKS289:print("P289_"+k+"="+q[k])
    print("P289_SOURCE_CHANGE_REVIEW="+decision)
    print("P289_INDEPENDENT_ORIGINAL_P245_GATE=UNMODIFIED")
    print("P289_NO_RENDERED_METHOD_REFERENCE_SUBSTITUTION=YES")
    print("P289_REPLACEMENT_IN_MAINLINE=NOT_AUTHORIZED")
    print("P289_ART_P192_B3_B4=NOT_ATTESTED")
    print("P289_PRIVATE_VALUES_FIELDS_PCS=WITHHELD")
    print("P289_RELEASE=DENY")
    print("P289_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for name in ("signed-original","base","candidate"):
        p.add_argument("--"+name,type=Path)
    x=p.parse_args()
    paths=(x.signed_original,x.base,x.candidate)
    if all(v is None for v in paths):
        print("P289_SOURCE_ONLY=YES")
        print("P289_REAL_RAW_METHOD_REF=NOT_ATTESTED")
        print("P289_RELEASE=DENY")
        print("P289_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"THREE_PINNED_INPUTS")
        seal(x.signed_original)
        return emit(judge(load(x.base),load(x.candidate)))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P289_DENY_UNEXPECTED"
        print(code,file=sys.stderr);return 2
if __name__=="__main__":
    raise SystemExit(main())
