#!/usr/bin/env python3
"""P281: independent five-part P245 helper-predicate audit; private DENY only.

The original P245 verifier is NOT imported as a gate, monkeypatched or edited.
We independently reproduce exactly its five aggregate conditions and inspect
raw method-pool refs and catch-table topology as supplementary diagnostics.
Logs contain fixed categorical fields only; no private descriptor, PC, raw
register, instruction output or helper-body bytes leave the runner.
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
]
from p246_exception_semantics import index, load, need, decode
from p249_dual_diff import seal
from p267_invoke_words import raw_words
from p269_method_pool import method_pool

OWNER="Lcom/dsh/android/EngineManager$start$2;"
NAME="p245Observe$ci"
DESC="("+OWNER+")V"
GETTER=("Lcom/dsh/android/EngineManager;","access$getProcess$p",
        "(Lcom/dsh/android/EngineManager;)","Ljava/lang/Process;")
LOG=("Landroid/util/Log;","i","(Ljava/lang/String;Ljava/lang/String;)","I")
GETTER_OUTPUT=GETTER[0]+"->"+GETTER[1]+GETTER[2]+GETTER[3]
LOG_OUTPUT=LOG[0]+"->"+LOG[1]+LOG[2]+LOG[3]
PREDICATES=("ONE_TRY","ONE_IGET_OBJECT","TWO_INVOKE_STATIC",
            "GETTER_OUTPUT_PRESENT","LOG_I_OUTPUT_PRESENT")
POOL=("BOTH_EXACT","ONE_OR_MORE_DIFFER","UNVERIFIED")
HANDLER=("ONE_TYPED_THROWABLE_MOVE_EXCEPTION","DIFFERENT","UNVERIFIED")
COUNTS=("IGET_OBJECT_COUNT","INVOKE_STATIC_COUNT","INVOKE_STATIC_RANGE_COUNT",
        "TRY_COUNT")
WITNESS=("ONE_ONLY","ABSENT","UNVERIFIED")
STATUS=("PASS","FAIL","UNVERIFIED")

def helper_rows(method):
    """A bounded direct instruction view, independent of verifier's ins()."""
    if method is None:return None
    getter=getattr(method,"get_instructions_idx",None)
    if not callable(getter):return None
    try:rows=list(getter())
    except Exception:return None
    if not 0<len(rows)<=1000000:return None
    result=[];cursor=0
    for pc,ins in rows:
        try: name,output,length=ins.get_name(),ins.get_output(),ins.get_length()
        except Exception:return None
        if (type(pc) is not int or type(length) is not int or
            pc!=cursor or length<=0 or length%2 or
            not isinstance(name,str) or not isinstance(output,str) or
            len(name)>128 or len(output)>8192):
            return None
        result.append((pc//2,name,length,ins,output))
        cursor+=length
    return tuple(result)

def p245_checks(method):
    """Exact P245 boolean predicates (not the P245 approval decision)."""
    rows=helper_rows(method)
    if rows is None or method is None:return None
    get=getattr(method,"get_code",None)
    try:code=get();try_count=code.get_tries_size()
    except Exception:return None
    if type(try_count) is not int or not (0<=try_count<=512):return None
    igets=sum(r[1]=="iget-object" for r in rows)
    calls=sum(r[1]=="invoke-static" for r in rows)
    ranges=sum(r[1]=="invoke-static/range" for r in rows)
    output="\n".join(r[4] for r in rows)
    values=(try_count==1,igets==1,calls==2,
            GETTER_OUTPUT in output,LOG_OUTPUT in output)
    return dict(predicates=dict(zip(PREDICATES,values)),
                counts=dict(zip(COUNTS,(igets,calls,ranges,try_count))),
                rows=rows)

def call_reference(method,rows,dex):
    """Independently resolve each 35c static method ref by raw DEX index."""
    found=[]
    for row in rows:
        if row[1]!="invoke-static":continue
        decoded=raw_words(row[:4])
        if decoded is None:return "UNVERIFIED"
        words,index_value=decoded
        ref=method_pool(dex,index_value)
        if ref is None:return "UNVERIFIED"
        try:
            code=method.get_code()
            outsz=code.get_outs_size()
            regsz=code.get_registers_size()
        except Exception:return "UNVERIFIED"
        if (type(outsz) is not int or type(regsz) is not int or
            len(words)>outsz or any(w>=regsz for w in words)):
            return "UNVERIFIED"
        found.append(ref)
    if len(found)!=2:return "UNVERIFIED"
    return "BOTH_EXACT" if sorted(found)==sorted((GETTER,LOG)) else "ONE_OR_MORE_DIFFER"

def catch_profile(method,dex,rows):
    """P246 canonical exception decode; check typed Throwable and entry."""
    try:
        decoded=decode(method,dex)
        cases=decoded[1]
        if len(cases)!=1:return "DIFFERENT"
        _,_,(typed,catchall)=cases[0]
        if len(typed)!=1 or typed[0][0]!="Ljava/lang/Throwable;":
            return "DIFFERENT"
        if catchall is not None:return "DIFFERENT"
        target=typed[0][1]
        if target not in {x[0] for x in rows}:return "DIFFERENT"
        x=next(r for r in rows if r[0]==target)
        return ("ONE_TYPED_THROWABLE_MOVE_EXCEPTION" if x[1]=="move-exception"
                else "DIFFERENT")
    except Exception:return "UNVERIFIED"

def audit(base_dex,candidate_dex):
    baseline=index(base_dex);candidate=index(candidate_dex)
    key=(OWNER,NAME,DESC)
    added=set(candidate)-set(baseline)
    if added!={key} or set(baseline)!=(set(candidate)-added):
        return dict(witness="UNVERIFIED",predicates={k:"UNVERIFIED" for k in PREDICATES},
                    counts={k:0 for k in COUNTS},pool="UNVERIFIED",handler="UNVERIFIED")
    m=candidate.get(key)
    observed=p245_checks(m)
    if observed is None:
        return dict(witness="ONE_ONLY",predicates={k:"UNVERIFIED" for k in PREDICATES},
                    counts={k:0 for k in COUNTS},pool="UNVERIFIED",handler="UNVERIFIED")
    checks={k:"PASS" if v else "FAIL" for k,v in observed["predicates"].items()}
    rows=observed["rows"]
    return dict(witness="ONE_ONLY",predicates=checks,counts=observed["counts"],
                pool=call_reference(m,rows,candidate_dex),
                handler=catch_profile(m,candidate_dex,rows))

def emit(q):
    need(type(q) is dict and set(q)=={"witness","predicates","counts","pool","handler"},
         "PUBLIC_SCHEMA")
    need(q["witness"] in WITNESS,"WITNESS_ENUM")
    checks=q["predicates"];counts=q["counts"]
    need(type(checks) is dict and set(checks)==set(PREDICATES) and
         all(x in STATUS for x in checks.values()),"PREDICATE_ENUM")
    need(type(counts) is dict and set(counts)==set(COUNTS) and
         all(type(n) is int and 0<=n<=1000000 for n in counts.values()),
         "COUNT_SCHEMA")
    need(q["pool"] in POOL and q["handler"] in HANDLER,"INDEPENDENT_ENUM")
    if q["witness"]!="ONE_ONLY":
        need(all(x=="UNVERIFIED" for x in checks.values()) and
             q["pool"]=="UNVERIFIED" and q["handler"]=="UNVERIFIED",
             "WITNESS_ABSENCE_DENY")
    if any(x=="UNVERIFIED" for x in checks.values()):
        need(all(x=="UNVERIFIED" for x in checks.values()),
             "ATOMIC_UNVERIFIED")
    else:
        need((checks["ONE_TRY"]=="PASS")== (counts["TRY_COUNT"]==1) and
             (checks["ONE_IGET_OBJECT"]=="PASS")== (counts["IGET_OBJECT_COUNT"]==1) and
             (checks["TWO_INVOKE_STATIC"]=="PASS")== (counts["INVOKE_STATIC_COUNT"]==2),
             "PREDICATE_COUNT_RECONCILE")
    for field in PREDICATES:
        print("P281_"+field+"="+checks[field])
    for field in COUNTS:
        print("P281_"+field+"="+str(counts[field]))
    print("P281_HELPER_WITNESS="+q["witness"])
    print("P281_RAW_METHOD_POOL="+q["pool"])
    print("P281_TYPED_CATCH="+q["handler"])
    print("P281_P245_COMBINED_PREDICATE="+
          ("PASS" if all(v=="PASS" for v in checks.values()) else "DENY"))
    print("P281_P245_EXISTING_FULL_GATE=UNMODIFIED")
    print("P281_PRIVATE_METHODS_OUTPUTS_PCS_REFS=WITHHELD")
    print("P281_ART_AND_ISOLATION_NOT_ATTESTED=YES")
    print("P281_RELEASE=DENY")
    print("P281_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for flag in ("signed-original","base","candidate"):
        p.add_argument("--"+flag,type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P281_SOURCE_ONLY=YES")
        print("P281_REAL_HELPER_CONDITIONS=NOT_ATTESTED")
        print("P281_RELEASE=DENY")
        print("P281_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"THREE_PINNED_INPUTS")
        seal(a.signed_original)
        base=load(a.base);candidate=load(a.candidate)
        return emit(audit(base,candidate))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P281_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
