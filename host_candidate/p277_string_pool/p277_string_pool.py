#!/usr/bin/env python3
"""P277 read-only direct DEX string-ID pool growth and threshold attribution.

Cross-check the ordered get_strings() table against independent get_cm_string(i)
for every item. For each pinned P275 21c->31c transition, compare the exact
pool index shift with newly added and removed string IDs preceding that index.
Even exact attribution to pool rank does not prove which source change caused
the insertion or grant executable equivalence. No IDs or private values output.
"""
import argparse
import re
import sys
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
 "host_candidate/p275_encoding_width",
]
from p246_exception_semantics import need,index,load,decode
from p249_dual_diff import seal,dual
from p253_cfg_ordinal import instructions
from p261_all_method_census import opaque
from p275_encoding_width import transition,string_index,pool_string

CAUSES=("EXACT_INSERTION_ONLY_SHIFT","EXACT_INSERTION_MINUS_REMOVAL_SHIFT",
        "COMMON_ORDER_CHANGED","RANK_EQUATION_FAILED",
        "RAW_INDEX_OR_POOL_UNVERIFIED","STRING_CONTENT_CHANGED",
        "REGISTER_CHANGED","NONCROSSING_OR_NOT_JUMBO")
ADDITION=("ADDED_BEFORE_EVERY_CROSSING","ADDED_BEFORE_SOME_CROSSINGS",
          "NO_ADDITIONS_BEFORE_CROSSINGS","UNKNOWN")
POOL_SEALS=("EXACT_ID_ORDER_VERIFIED","UNVERIFIED")

def indexed_strings(dex):
    """Check index addressability of every string; no unverified surrogate view."""
    getter=getattr(dex,"get_strings",None)
    by_index=getattr(dex,"get_cm_string",None)
    if not callable(getter) or not callable(by_index):return None
    try: data=getter()
    except Exception:return None
    if not isinstance(data,(tuple,list)) or not 0<len(data)<=1000000:return None
    if not all(isinstance(v,str) and len(v)<1000000 for v in data):return None
    if len(set(data))!=len(data):return None
    try:
        for idx,s in enumerate(data):
            if by_index(idx)!=s:return None
    except Exception:return None
    return tuple(data)

def pool_diff(original,candidate):
    """Return private index maps plus only aggregate metadata for export."""
    if original is None or candidate is None:return None
    if len(set(original))!=len(original) or len(set(candidate))!=len(candidate):
        return None
    a={v:i for i,v in enumerate(original)}
    b={v:i for i,v in enumerate(candidate)}
    before=set(a);after=set(b)
    added=after-before;removed=before-after
    common_a=tuple(s for s in original if s in after)
    common_b=tuple(s for s in candidate if s in before)
    preserved=common_a==common_b
    return dict(base=a,new=b,added=added,removed=removed,
                base_count=len(a),new_count=len(b),
                common_order=preserved)

def crossing(x,y,dex_a,dex_b,old_pool,new_pool,delta):
    """Return categorical cause and number of extra strings before a crossing."""
    if delta is None or old_pool is None or new_pool is None:
        return ("RAW_INDEX_OR_POOL_UNVERIFIED",0)
    if (x[1],y[1])!=("const-string","const-string/jumbo"):
        return ("NONCROSSING_OR_NOT_JUMBO",0)
    a=string_index(x[3],x[1]);b=string_index(y[3],y[1])
    if a is None or b is None:return ("RAW_INDEX_OR_POOL_UNVERIFIED",0)
    if a[0]!=b[0]:return ("REGISTER_CHANGED",0)
    old_i,new_i=a[1],b[1]
    if old_i>=len(old_pool) or new_i>=len(new_pool):
        return ("RAW_INDEX_OR_POOL_UNVERIFIED",0)
    sa=pool_string(dex_a,old_i);sb=pool_string(dex_b,new_i)
    if sa is None or sb is None or old_pool[old_i]!=sa or new_pool[new_i]!=sb:
        return ("RAW_INDEX_OR_POOL_UNVERIFIED",0)
    if sa!=sb:return ("STRING_CONTENT_CHANGED",0)
    if not (old_i<=65535 and new_i>65535):
        return ("NONCROSSING_OR_NOT_JUMBO",0)
    if not delta["common_order"]:
        return ("COMMON_ORDER_CHANGED",0)
    inserted=sum(1 for z in new_pool[:new_i] if z in delta["added"])
    removed=sum(1 for z in old_pool[:old_i] if z in delta["removed"])
    if new_i-old_i!=inserted-removed:
        return ("RANK_EQUATION_FAILED",inserted)
    return (("EXACT_INSERTION_MINUS_REMOVAL_SHIFT" if removed else
             "EXACT_INSERTION_ONLY_SHIFT"),inserted)

def audit(base_dex,derived_dex):
    original=index(base_dex);derived=index(derived_dex)
    previous=dual(original,derived,base_dex,derived_dex)
    old_pool=indexed_strings(base_dex);new_pool=indexed_strings(derived_dex)
    delta=pool_diff(old_pool,new_pool)
    causes=Counter({k:0 for k in CAUSES})
    checked=0
    added_before=[]
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None or opaque(a) or opaque(b):continue
        l,r=decode(a,base_dex),decode(b,derived_dex)
        left,right=instructions(a,l),instructions(b,r)
        if len(left)!=len(right):continue
        for x,y in zip(left,right):
            if transition(x[1],y[1],x[2],y[2])[0]!="STRING_TO_JUMBO":
                continue
            cause,added=crossing(x,y,base_dex,derived_dex,old_pool,new_pool,delta)
            need(cause in CAUSES,"CAUSE")
            causes[cause]+=1
            checked+=1
            added_before.append(added)
    need(checked>0,"NO_CROSSING")
    if delta is None:
        label="UNKNOWN"
        counts=(0,0,0,0)
        poolseal="UNVERIFIED"
    else:
        counts=(delta["base_count"],delta["new_count"],
                len(delta["added"]),len(delta["removed"]))
        poolseal="EXACT_ID_ORDER_VERIFIED"
        if checked and all(n>0 for n in added_before):
            label="ADDED_BEFORE_EVERY_CROSSING"
        elif any(n>0 for n in added_before):
            label="ADDED_BEFORE_SOME_CROSSINGS"
        else:label="NO_ADDITIONS_BEFORE_CROSSINGS"
    need(label in ADDITION and poolseal in POOL_SEALS,"ADDITION_CLASS")
    return dict(causes=dict(causes),checked=checked,base_count=counts[0],
                new_count=counts[1],added_count=counts[2],removed_count=counts[3],
                pool_seal=poolseal,preceding_additions=label,
                code_gate=previous["code_gate"],exception_gate=previous["exception_gate"])

def emit(q):
    fields=("causes","checked","base_count","new_count","added_count",
            "removed_count","pool_seal","preceding_additions",
            "code_gate","exception_gate")
    need(type(q) is dict and set(q)==set(fields),"OUTPUT_SCHEMA")
    n=q["checked"]
    need(type(n) is int and 0<n<=1000000,"CHECKED_RANGE")
    need(type(q["causes"]) is dict and set(q["causes"])==set(CAUSES) and
         all(type(v) is int and 0<=v<=n for v in q["causes"].values()) and
         sum(q["causes"].values())==n,"CAUSE_RECONCILIATION")
    need(all(type(q[k]) is int and 0<=q[k]<=1000000 for k in
             ("base_count","new_count","added_count","removed_count")),
         "POOL_COUNT_RANGE")
    need(q["pool_seal"] in POOL_SEALS and q["preceding_additions"] in ADDITION,
         "POOL_SEAL")
    if q["pool_seal"]=="EXACT_ID_ORDER_VERIFIED":
        need(q["new_count"]-q["base_count"]==
             q["added_count"]-q["removed_count"],"POOL_SIZE_RECONCILIATION")
    else:
        need(q["preceding_additions"]=="UNKNOWN" and
             all(q[k]==0 for k in ("base_count","new_count","added_count",
                                   "removed_count")),"UNVERIFIED_POOL_RECONCILIATION")
    need(q["code_gate"]=="DENY" and q["exception_gate"]=="DENY",
         "EXISTING_FULL_DENY")
    for k in CAUSES:print("P277_CAUSE_"+k+"="+str(q["causes"][k]))
    for label,key in (("ORIGINAL_POOL_STRINGS","base_count"),
                      ("CANDIDATE_POOL_STRINGS","new_count"),
                      ("ADDED_POOL_STRINGS","added_count"),
                      ("REMOVED_POOL_STRINGS","removed_count"),
                      ("STRING_JUMBO_CROSSINGS","checked")):
        print("P277_"+label+"="+str(q[key]))
    print("P277_POOL_ID_INDEX_SEAL="+q["pool_seal"])
    print("P277_ADDITIONS_PRECEDING_CROSSINGS="+q["preceding_additions"])
    print("P277_POOL_INSERTION_SOURCE_CAUSALITY=NOT_ATTESTED")
    print("P277_PRIVATE_STRINGS_POOL_INDICES_METHODS_PCS=WITHHELD")
    print("P277_P245_AND_ART=NOT_ATTESTED")
    print("P277_RELEASE=DENY")
    print("P277_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for x in ("signed-original","base","candidate"):
        p.add_argument("--"+x,type=Path)
    args=p.parse_args()
    paths=(args.signed_original,args.base,args.candidate)
    if all(x is None for x in paths):
        print("P277_SOURCE_ONLY=YES")
        print("P277_REAL_POOL_ORDER=NOT_ATTESTED")
        print("P277_RELEASE=DENY")
        print("P277_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"PINNED_INPUTS")
        seal(args.signed_original)
        db=load(args.base);dc=load(args.candidate)
        return emit(audit(db,dc))
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P277_DENY_UNEXPECTED"
        print(code,file=sys.stderr);return 2
if __name__=="__main__":
    raise SystemExit(main())
