#!/usr/bin/env python3
"""P269: private, deny-only independent method-pool resolution of P268 unknown.

The 35c zero-argument operand-list omission is an API behavior to TEST, not
a presumption about the original DEX. No method identifiers or values printed.
No changes to P245/P267/P192/P47, no release permission.
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
             "host_candidate/p261_all_method_census",
             "host_candidate/p263_operand_correlation",
             "host_candidate/p265_operand_shape",
             "host_candidate/p267_invoke_words"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p261_all_method_census import method_observation,opaque
from p259_all_operands import pair
from p263_operand_correlation import changed_kind
from p265_operand_shape import shape_cause
from p267_invoke_words import (report as p267_report,raw_words,classify,
       type_widths,wide_valid,FIXED,RANGE,CAUSES as P267_CAUSES)
CATEGORIES=("ZERO_WORD_35C_OMISSION_POOL_MATCH_CANDIDATE",
 "ZERO_WORD_POOL_METHOD_DIFFER","ZERO_WORD_EXPECTED_ARGUMENTS_NONZERO",
 "ZERO_WORD_NONSTATIC_RECEIVER_INVALID","NONZERO_METHOD_POOL_MATCH_CANDIDATE",
 "NONZERO_METHOD_POOL_DIFFER","NONZERO_REGISTER_WORDS_DIFFER",
 "NONZERO_WIDE_LAYOUT_INVALID","POOL_METHOD_REFERENCE_UNAVAILABLE",
 "LIBRARY_REFERENCE_VIEW_NOT_RECONCILED","RAW_OR_ENCODING_UNVERIFIED",
 "MULTIPLE_MISMATCHES_UNVERIFIED","OTHER_NOT_ATTESTED")

def method_pool(dex,ref_idx):
    getter=getattr(dex,"get_cm_method",None)
    if not callable(getter):return None
    try:item=getter(ref_idx)
    except Exception:return None
    if not isinstance(item,(list,tuple)) or len(item)!=3:return None
    cls,name,proto=item
    if not isinstance(cls,str) or not re.fullmatch(r"L[^;()\s]+;",cls):return None
    if not isinstance(name,str) or not (0<len(name)<=8192) or re.search(r"[()\s]",name):return None
    if not isinstance(proto,(list,tuple)) or len(proto)!=2 or not all(isinstance(v,str) for v in proto):return None
    args,ret=proto
    if not args.startswith("(") or not args.endswith(")"):return None
    if len(args)+len(ret)>8192:return None
    return (cls,name,args,ret)

def library_zero_view(row,idx):
    """Explicitly confirm the parser-side omission without guessing raw refs."""
    get=getattr(row[3],"get_operands",None)
    if not callable(get):return False
    try:items=get()
    except Exception:return False
    return isinstance(items,(list,tuple)) and len(items)==0

def signature(ref):
    return ref[0]+"->"+ref[1]+ref[2]+ref[3]

def classify_pool(a,b,ma,mb,da,db):
    na,nb=a[1],b[1]
    if (na not in FIXED or nb not in RANGE) and (nb not in FIXED or na not in RANGE):
        return "RAW_OR_ENCODING_UNVERIFIED"
    if na.removesuffix("/range")!=nb.removesuffix("/range"):
        return "RAW_OR_ENCODING_UNVERIFIED"
    xa,xb=raw_words(a),raw_words(b)
    if xa is None or xb is None:return "RAW_OR_ENCODING_UNVERIFIED"
    wa,ia=xa;wb,ib=xb
    if len(wa)!=len(wb) or wa!=wb:return "NONZERO_REGISTER_WORDS_DIFFER"
    try:
        sizes=(ma.get_code().get_registers_size(),mb.get_code().get_registers_size())
        outs=(ma.get_code().get_outs_size(),mb.get_code().get_outs_size())
    except Exception:return "RAW_OR_ENCODING_UNVERIFIED"
    if any(type(v) is not int or v<0 or v>65535 for v in sizes+outs):return "RAW_OR_ENCODING_UNVERIFIED"
    if sizes[0]!=sizes[1] or outs[0]!=outs[1] or len(wa)>min(outs) or any(v>=min(sizes) for v in wa):
        return "RAW_OR_ENCODING_UNVERIFIED"
    pa,pb=method_pool(da,ia),method_pool(db,ib)
    if pa is None or pb is None:return "POOL_METHOD_REFERENCE_UNAVAILABLE"
    if pa!=pb:
        return "ZERO_WORD_POOL_METHOD_DIFFER" if not wa else "NONZERO_METHOD_POOL_DIFFER"
    static=na.startswith("invoke-static") and nb.startswith("invoke-static")
    widths=type_widths(signature(pa),static)
    if widths is None:return "POOL_METHOD_REFERENCE_UNAVAILABLE"
    if not wa:
        if not static:return "ZERO_WORD_NONSTATIC_RECEIVER_INVALID"
        if widths:return "ZERO_WORD_EXPECTED_ARGUMENTS_NONZERO"
        fixed=a if na in FIXED else b
        if not library_zero_view(fixed,ia if na in FIXED else ib):
            return "LIBRARY_REFERENCE_VIEW_NOT_RECONCILED"
        return "ZERO_WORD_35C_OMISSION_POOL_MATCH_CANDIDATE"
    if not wide_valid(wa,widths):return "NONZERO_WIDE_LAYOUT_INVALID"
    # Nonzero P267 reference failure requires separate strict explanation;
    # pool-level equality alone does not validate the library operand view.
    return "NONZERO_METHOD_POOL_MATCH_CANDIDATE"

def audit(original,derived,da,db):
    prior=p267_report(original,derived,da,db)
    n=prior["causes"]["INVOKE_REFERENCE_NOT_ATTESTED"]
    out=Counter({k:0 for k in CATEGORIES})
    observed=0
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        la,lb=decode(a,da),decode(b,db)
        if not method_observation(a,b,da,db,la,lb)["OPERANDS_STRUCTURED_DIFFER"]:continue
        if opaque(a) or opaque(b):continue
        ra,rb=instructions(a,la),instructions(b,lb)
        if len(ra)!=len(rb):continue
        pairs=[(x,y) for x,y in zip(ra,rb) if pair(x,y)=="STRUCTURED_DIFFER"]
        target=[(x,y) for x,y in pairs if changed_kind(x,y)=="OPERAND_SHAPE" and
                shape_cause(x,y)=="NORMALIZED_ITEM_COUNT"]
        if len(target)!=1 or len(pairs)!=1:continue
        x,y=target[0]
        if classify(x,y,a,b)!="INVOKE_REFERENCE_NOT_ATTESTED":continue
        cat=classify_pool(x,y,a,b,da,db)
        need(cat in CATEGORIES,"P269_CATEGORY")
        out[cat]+=1;observed+=1
    need(n==observed,"P268_REF_UNKNOWN_RECONCILIATION")
    return dict(counts=dict(out),ref_unknown=n,prior_unknown=prior["unknown"],
                matched_candidates=prior["causes"]["INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE"])
def emit(q):
    need(type(q) is dict and set(q)=={"counts","ref_unknown","prior_unknown","matched_candidates"},"OUTPUT_SCHEMA")
    c=q["counts"];n=q["ref_unknown"]
    need(type(c) is dict and set(c)==set(CATEGORIES),"OUTPUT_CATEGORIES")
    need(all(type(v) is int and 0<=v<=1000000 for v in (n,q["prior_unknown"],q["matched_candidates"])),
         "OUTPUT_RANGE")
    need(all(type(x) is int and 0<=x<=n for x in c.values()) and sum(c.values())==n,
         "OUTPUT_RECONCILIATION")
    for k in CATEGORIES:print("P269_"+k+"="+str(c[k]))
    print("P269_PRIOR_REF_UNVERIFIED="+str(n))
    print("P269_PRIOR_UNVERIFIED_METHODS="+str(q["prior_unknown"]))
    print("P269_POOL_MATCH_IS_ONLY_CANDIDATE=YES")
    print("P269_ORIGINAL_METHOD_IDENTITIES_AND_PARAMETERS=WITHHELD")
    print("P269_ART_AND_COMPLETE_P245=NOT_ATTESTED")
    print("P269_RELEASE=DENY")
    print("P269_V139=STRUCTURAL_BLOCKED")
    return 2
def main():
    ap=argparse.ArgumentParser()
    for flag in ("signed-original","base","candidate"):
        ap.add_argument("--"+flag,type=Path)
    a=ap.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P269_SOURCE_ONLY=YES")
        print("P269_REAL_METHOD_POOL=NOT_ATTESTED")
        print("P269_RELEASE=DENY")
        print("P269_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):code="P269_DENY_UNEXPECTED"
        print(code,file=sys.stderr);return 2
if __name__=="__main__":raise SystemExit(main())
