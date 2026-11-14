#!/usr/bin/env python3
"""P287 standalone, deny-only review of a MINIMAL P245 log-text predicate delta.

This script PROPOSES an extra verifier condition for independent review; it
never edits/imports P245 or promotes an APK. The first four original P245
predicates MUST remain PASS, the fifth must fail solely because exactly one
ASCII separator sits between complete Java String argument type descriptors.
Independently prove all 11 P285 structural factors, both canonical raw
method references, original source seal, and P281 typed Throwable catch.
The only possible positive category is SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE.
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
]
from p246_exception_semantics import index,load,need
from p249_dual_diff import seal
from p281_helper_predicates import (
    OWNER,NAME,DESC,p245_checks,catch_profile,call_reference,PREDICATES)
from p283_descriptor_normalization import (
    audit as p283_audit,DETAIL,classify_detail)
from p285_shadow_verifier import audit as p285_audit,FACTORS

SINGLE_LOG=re.compile(
 r"v1, v2, Landroid/util/Log;->i\(Ljava/lang/String;[ \t]+Ljava/lang/String;\)I\Z",
 re.ASCII)
OUTCOMES=("SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE",
          "DENY_DIFFERENT_OR_UNVERIFIED")
CHECKS=("ORIGINAL_FOUR_PREDICATES","LEGACY_TEXT_ONLY_FAIL",
        "EXACT_ONE_ASCII_SEPARATOR",
        "CANONICAL_RAW_GETTER",
        "CANONICAL_RAW_LOG",
        "HELPER_ORIGINAL_TYPED_CATCH",
        "P285_ALL_ELEVEN_FACTORS")
STATES=("PASS","FAIL","UNVERIFIED")

def display_shape(value):
    if not isinstance(value,str) or len(value)>8192:
        return "UNVERIFIED"
    return "PASS" if SINGLE_LOG.fullmatch(value) else "FAIL"

def candidate(original_predicates,original_catch,raw_getter,raw_log,shadow,
              log_output):
    """Pure independent decision function; never a build/release gate."""
    checks={x:"UNVERIFIED" for x in CHECKS}
    if (type(original_predicates) is dict and set(original_predicates)==set(PREDICATES)
        and all(x in STATES for x in original_predicates.values())):
        first=PREDICATES[:4]
        checks["ORIGINAL_FOUR_PREDICATES"]=(
          "PASS" if all(original_predicates[x]=="PASS" for x in first) else
          "FAIL" if any(original_predicates[x]=="FAIL" for x in first) else "UNVERIFIED")
        checks["LEGACY_TEXT_ONLY_FAIL"]=(
          "PASS" if original_predicates[PREDICATES[4]]=="FAIL" else
          "FAIL" if original_predicates[PREDICATES[4]]=="PASS" else "UNVERIFIED")
    checks["EXACT_ONE_ASCII_SEPARATOR"]=display_shape(log_output)
    if isinstance(raw_getter,dict) and set(raw_getter)==set(DETAIL):
        checks["CANONICAL_RAW_GETTER"]=(
          "PASS" if classify_detail(raw_getter)=="EXACT" else
          "UNVERIFIED" if classify_detail(raw_getter)=="UNVERIFIED" else "FAIL")
    if isinstance(raw_log,dict) and set(raw_log)==set(DETAIL):
        checks["CANONICAL_RAW_LOG"]=(
          "PASS" if (classify_detail(raw_log)=="FORMAT_ONLY_CANDIDATE"
              and raw_log["RAW_ARGS_EXACT"]=="FAIL"
              and raw_log["RAW_ARGS_CANONICAL"]=="PASS"
              and raw_log["OUTPUT_TEXT_EXACT"]=="FAIL"
              and raw_log["OUTPUT_TEXT_CANONICAL"]=="PASS") else
          "UNVERIFIED" if classify_detail(raw_log)=="UNVERIFIED" else "FAIL")
    checks["HELPER_ORIGINAL_TYPED_CATCH"]=(
      "PASS" if original_catch=="ONE_TYPED_THROWABLE_MOVE_EXCEPTION" else
      "UNVERIFIED" if original_catch=="UNVERIFIED" else "FAIL")
    if type(shadow) is dict and set(shadow)==set(FACTORS):
        checks["P285_ALL_ELEVEN_FACTORS"]=(
          "PASS" if all(x=="PASS" for x in shadow.values()) else
          "FAIL" if any(x=="FAIL" for x in shadow.values()) else "UNVERIFIED")
    if all(x=="PASS" for x in checks.values()):
        verdict="SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE"
    else:verdict="DENY_DIFFERENT_OR_UNVERIFIED"
    return (checks,verdict)

def audit(base_dex,candidate_dex):
    base=index(base_dex);derived=index(candidate_dex)
    if (set(derived)-set(base)!={(OWNER,NAME,DESC)} or
        set(base)!=set(derived)-{(OWNER,NAME,DESC)}):
        return candidate(None,"UNVERIFIED",None,None,None,None)
    target=derived[(OWNER,NAME,DESC)]
    p281=p245_checks(target)
    if p281 is None:return candidate(None,"UNVERIFIED",None,None,None,None)
    rows=p281["rows"]
    output=rows[10][4] if len(rows)==14 and rows[10][1]=="invoke-static" else None
    observed={k:"PASS" if v else "FAIL" for k,v in p281["predicates"].items()}
    catch=catch_profile(target,candidate_dex,rows)
    refs=p283_audit(base_dex,candidate_dex)
    strict=p285_audit(base_dex,candidate_dex)
    return candidate(observed,catch,refs["calls"]["GETTER"],
                     refs["calls"]["LOG"],strict,output)

def emit(q):
    need(type(q) in (list,tuple) and len(q)==2,"PUBLIC_RESULT")
    checks,verdict=q
    need(type(checks) is dict and set(checks)==set(CHECKS) and
         all(v in STATES for v in checks.values()),"PUBLIC_SCHEMA")
    need(verdict in OUTCOMES,"PUBLIC_OUTCOME")
    if verdict=="SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE":
        need(all(v=="PASS" for v in checks.values()),"STRICT_ALL_PASS_REQUIRED")
    for x in CHECKS:
        print("P287_"+x+"="+checks[x])
    print("P287_LOG_TEXT_REPLACEMENT_REVIEW="+verdict)
    print("P287_ORIGINAL_P245_VERIFIER=UNCHANGED")
    print("P287_P285_SHADOW_IS_NOT_P245_GATE=YES")
    print("P287_NO_ORIGINAL_METHODS_STRINGS_REGISTERS_OR_PCS=YES")
    print("P287_REPLACEMENT_APPROVAL=NOT_GRANTED")
    print("P287_ART_ISOLATION_AND_P192=NOT_ATTESTED")
    print("P287_RELEASE=DENY")
    print("P287_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    parser=argparse.ArgumentParser()
    for n in ("signed-original","base","candidate"):
        parser.add_argument("--"+n,type=Path)
    x=parser.parse_args()
    paths=(x.signed_original,x.base,x.candidate)
    if all(v is None for v in paths):
        print("P287_SOURCE_ONLY=YES")
        print("P287_REAL_DELTA_REVIEW=NOT_ATTESTED")
        print("P287_RELEASE=DENY")
        print("P287_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"PINNED_THREE_INPUTS")
        seal(x.signed_original)
        return emit(audit(load(x.base),load(x.candidate)))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P287_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
