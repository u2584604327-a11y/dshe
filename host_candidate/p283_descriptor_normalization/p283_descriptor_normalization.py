#!/usr/bin/env python3
"""P283: independent literal-vs-grammatical DEX call target normalization.

Disambiguate true method-pool drift from Androguard's two-parameter display
spacing without editing original P245, DEX bytes or a verifier condition.
Only validated ASCII inter-type separators may be normalized. Private method
names, register values, offsets, raw descriptors and outputs are NEVER logged.
All real-input executions remain release-denied, regardless of agreement.
"""
import argparse
import re
import sys
from pathlib import Path
sys.path[:0]=[
  "host_candidate/p246_exception_semantics",
  "host_candidate/p249_dual_diff",
  "host_candidate/p267_invoke_words",
  "host_candidate/p269_method_pool",
  "host_candidate/p281_helper_predicates",
]
from p246_exception_semantics import index,load,need
from p249_dual_diff import seal
from p267_invoke_words import raw_words
from p269_method_pool import method_pool
from p281_helper_predicates import helper_rows,OWNER,NAME,DESC,GETTER,LOG

DETAIL=("RAW_WORD_COUNT","RAW_OWNER","RAW_NAME","RAW_RETURN",
        "RAW_ARGS_EXACT","RAW_ARGS_CANONICAL","RAW_CANONICAL_TUPLE",
        "OUTPUT_TEXT_EXACT","OUTPUT_TEXT_CANONICAL")
CALLS=("GETTER","LOG")
VALUES=("PASS","FAIL","UNVERIFIED")
SUMMARY=("EXACT","FORMAT_ONLY_CANDIDATE","DIFFERENT_OR_INVALID","UNVERIFIED")

TOKEN=re.compile(r"[ \t]*(\[*L[^;()\s]+;|\[*[ZBCSIFJD])[ \t]*")

def canonical_args(value):
    """Parse full descriptor; only strip whitespace *between* complete types."""
    if (not isinstance(value,str) or len(value)>8192 or
        not value.startswith("(") or not value.endswith(")")):
        return None
    body=value[1:-1]
    pos=0;types=[]
    while pos<len(body):
        m=TOKEN.match(body,pos)
        if m is None or m.end()<=pos:return None
        types.append(m.group(1))
        pos=m.end()
    if pos!=len(body):return None
    return "("+"".join(types)+")"

def canonical_return(value):
    if not isinstance(value,str) or len(value)>8192:return None
    s=value.strip(" \t")
    if re.fullmatch(r"V|\[*L[^;()\s]+;|\[*[ZBCSIFJD]",s):
        return s
    return None

def call_detail(row,dex,expected,expected_words):
    """Raw 35c method-ID parsing and independent display checks."""
    values={x:"UNVERIFIED" for x in DETAIL}
    if (not isinstance(row,(list,tuple)) or len(row)!=5 or
        row[1]!="invoke-static" or not isinstance(row[4],str)):
        return values
    display=row[4]
    exact=expected[0]+"->"+expected[1]+expected[2]+expected[3]
    values["OUTPUT_TEXT_EXACT"]="PASS" if exact in display else "FAIL"
    values["OUTPUT_TEXT_CANONICAL"]=(
        "PASS" if exact in re.sub(r"[ \t]+","",display) else "FAIL")
    raw=raw_words(row[:4])
    if raw is None:return values
    words,index_value=raw
    values["RAW_WORD_COUNT"]="PASS" if len(words)==expected_words else "FAIL"
    ref=method_pool(dex,index_value)
    if ref is None:return values
    a,b,args,ret=ref
    values["RAW_OWNER"]="PASS" if a==expected[0] else "FAIL"
    values["RAW_NAME"]="PASS" if b==expected[1] else "FAIL"
    values["RAW_RETURN"]=(
        "UNVERIFIED" if canonical_return(ret) is None else
        "PASS" if canonical_return(ret)==expected[3] else "FAIL")
    values["RAW_ARGS_EXACT"]="PASS" if args==expected[2] else "FAIL"
    canargs=canonical_args(args)
    values["RAW_ARGS_CANONICAL"]=(
        "UNVERIFIED" if canargs is None else
        "PASS" if canargs==expected[2] else "FAIL")
    subset=(values["RAW_OWNER"],values["RAW_NAME"],values["RAW_RETURN"],
            values["RAW_ARGS_CANONICAL"])
    values["RAW_CANONICAL_TUPLE"]=(
        "PASS" if all(x=="PASS" for x in subset) else
        "FAIL" if any(x=="FAIL" for x in subset) else "UNVERIFIED")
    return values

def classify_detail(q):
    if type(q) is not dict or set(q)!=set(DETAIL) or any(v not in VALUES for v in q.values()):
        return "UNVERIFIED"
    if any(q[x]=="UNVERIFIED" for x in (
        "RAW_WORD_COUNT","RAW_CANONICAL_TUPLE",
        "OUTPUT_TEXT_EXACT","OUTPUT_TEXT_CANONICAL")):
        return "UNVERIFIED"
    if q["RAW_WORD_COUNT"]!="PASS" or q["RAW_CANONICAL_TUPLE"]!="PASS":
        return "DIFFERENT_OR_INVALID"
    if q["OUTPUT_TEXT_EXACT"]=="PASS":return "EXACT"
    if q["OUTPUT_TEXT_CANONICAL"]=="PASS":
        return "FORMAT_ONLY_CANDIDATE"
    return "DIFFERENT_OR_INVALID"

def audit(base_dex,candidate_dex):
    original=index(base_dex);derived=index(candidate_dex)
    key=(OWNER,NAME,DESC)
    add=set(derived)-set(original)
    if add!={key} or set(original)!=(set(derived)-add):
        return {"witness":"UNVERIFIED","calls":{c:{k:"UNVERIFIED" for k in DETAIL}
                                               for c in CALLS}}
    rows=helper_rows(derived[key])
    statics=[] if rows is None else [r for r in rows if r[1]=="invoke-static"]
    if len(statics)!=2:
        return {"witness":"UNVERIFIED","calls":{c:{k:"UNVERIFIED" for k in DETAIL}
                                               for c in CALLS}}
    return {"witness":"ONE_ONLY","calls":{
        "GETTER":call_detail(statics[0],candidate_dex,GETTER,1),
        "LOG":call_detail(statics[1],candidate_dex,LOG,2)}}

def emit(q):
    need(type(q) is dict and set(q)=={"witness","calls"},"OUTPUT_SHAPE")
    need(q["witness"] in ("ONE_ONLY","UNVERIFIED"),"WITNESS_ENUM")
    need(type(q["calls"]) is dict and set(q["calls"])==set(CALLS),"CALL_SET")
    for c in CALLS:
        detail=q["calls"][c]
        need(type(detail) is dict and set(detail)==set(DETAIL) and
             all(v in VALUES for v in detail.values()),"DETAIL_SCHEMA")
        if q["witness"]!="ONE_ONLY":
            need(all(v=="UNVERIFIED" for v in detail.values()),"MISSING_WITNESS_DENY")
        need(detail["RAW_CANONICAL_TUPLE"]!="PASS" or
             all(detail[k]=="PASS" for k in ("RAW_OWNER","RAW_NAME","RAW_RETURN",
                                            "RAW_ARGS_CANONICAL")),"CANONICAL_RECONCILE")
        need(detail["OUTPUT_TEXT_EXACT"]!="PASS" or
             detail["OUTPUT_TEXT_CANONICAL"]=="PASS","DISPLAY_RECONCILE")
    print("P283_HELPER_WITNESS="+q["witness"])
    for c in CALLS:
        for field in DETAIL:
            print("P283_"+c+"_"+field+"="+q["calls"][c][field])
        v=classify_detail(q["calls"][c])
        need(v in SUMMARY,"SUMMARY_ENUM")
        print("P283_"+c+"_CLASS="+v)
    print("P283_INTER_TYPE_SPACING_NORMALIZATION=DIAGNOSTIC_ONLY")
    print("P283_ORIGINAL_P245_STRING_PREDICATE=UNMODIFIED")
    print("P283_ART_PROCESS_OWNERSHIP_AND_P192=NOT_ATTESTED")
    print("P283_PRIVATE_METHODS_PCS_REFS_REGISTER_VALUES=WITHHELD")
    print("P283_RELEASE=DENY")
    print("P283_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for name in ("signed-original","base","candidate"):
        p.add_argument("--"+name,type=Path)
    args=p.parse_args()
    paths=(args.signed_original,args.base,args.candidate)
    if all(v is None for v in paths):
        print("P283_SOURCE_ONLY=YES")
        print("P283_REAL_INVOCATION_DESCRIPTOR=NOT_ATTESTED")
        print("P283_RELEASE=DENY")
        print("P283_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"THREE_PINNED_INPUTS")
        seal(args.signed_original)
        return emit(audit(load(args.base),load(args.candidate)))
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P283_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
