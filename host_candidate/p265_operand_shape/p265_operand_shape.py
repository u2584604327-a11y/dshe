#!/usr/bin/env python3
"""P265: privacy-safe subcategory of P263 original operand-SHAPE divergence.

This is an observational diagnostic, not instruction equivalence. Raw values,
method IDs, constants, register indices, descriptors and PCs MUST NOT escape.
Do not change P245/P47/ART/owner gates or consume any actual browser data.
"""
import argparse,re,sys
from pathlib import Path
from collections import Counter
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family",
              "host_candidate/p259_all_operands",
              "host_candidate/p261_all_method_census",
              "host_candidate/p263_operand_correlation"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p259_all_operands import operands,pair
from p261_all_method_census import method_observation,opaque
from p263_operand_correlation import diagnose,mismatch_types,changed_kind

CAUSES=("NORMALIZED_ITEM_COUNT","NORMALIZED_ITEM_KIND",
        "RAW_ITEM_COUNT","RAW_TAG_ORDER","RAW_ITEM_ARITY",
        "RAW_LAYOUT_SAME_UNATTESTED","ONE_SIDE_UNDECODABLE",
        "BOTH_SIDES_UNDECODABLE","NORMALIZED_VALUES_CHANGED",
        "OTHER_NOT_ATTESTED")
def raw_signature(ins):
    getter=getattr(ins,"get_operands",None)
    if not callable(getter):return None
    try:seq=getter()
    except Exception:return None
    if not isinstance(seq,(list,tuple)) or len(seq)>256:return None
    out=[]
    for item in seq:
        if not isinstance(item,(list,tuple)) or not (2<=len(item)<=4):
            return None
        tag=item[0]
        if not isinstance(tag,int) or isinstance(tag,bool):return None
        out.append((tag,len(item)))
    return tuple(out)

def shape_cause(x,y):
    """Return *only* a fixed enum, with no sensitive values or identifiers."""
    left,right=x[1],y[1]
    na,nb=operands(x[3],left),operands(y[3],right)
    if na is not None and nb is not None:
        if na==nb:return "OTHER_NOT_ATTESTED"
        if len(na)!=len(nb):return "NORMALIZED_ITEM_COUNT"
        if tuple(v[0] for v in na)!=tuple(v[0] for v in nb):
            return "NORMALIZED_ITEM_KIND"
        return "NORMALIZED_VALUES_CHANGED" # not proof of cause or equivalence
    ra,rb=raw_signature(x[3]),raw_signature(y[3])
    if ra is None and rb is None:return "BOTH_SIDES_UNDECODABLE"
    if ra is None or rb is None:return "ONE_SIDE_UNDECODABLE"
    if len(ra)!=len(rb):return "RAW_ITEM_COUNT"
    if tuple(tag for tag,_ in ra)!=tuple(tag for tag,_ in rb):
        return "RAW_TAG_ORDER"
    if ra!=rb:return "RAW_ITEM_ARITY"
    return "RAW_LAYOUT_SAME_UNATTESTED"

def report(original,derived,da,db):
    previous=diagnose(original,derived,da,db)
    shape_methods=previous["counts"]["DIVERGENT_OPERAND_SHAPE"]
    out=Counter({c:0 for c in CAUSES})
    recorded=0
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        la,lb=decode(a,da),decode(b,db)
        flags=method_observation(a,b,da,db,la,lb)
        if not flags["OPERANDS_STRUCTURED_DIFFER"]:continue
        if opaque(a) or opaque(b):continue
        ra,rb=instructions(a,la),instructions(b,lb)
        if len(ra)!=len(rb):continue
        mismatch=mismatch_types(a,b,da,db)
        if "OPERAND_SHAPE" not in mismatch:continue
        first=None
        for x,y in zip(ra,rb):
            if pair(x,y)!="STRUCTURED_DIFFER":continue
            if changed_kind(x,y)=="OPERAND_SHAPE":
                first=shape_cause(x,y)
                break
        if first is None:first="OTHER_NOT_ATTESTED"
        need(first in CAUSES,"CAUSE_ENUM")
        out[first]+=1
        recorded+=1
    need(recorded==shape_methods,"P263_SHAPE_RECONCILIATION")
    need(sum(out.values())==shape_methods,"CAUSE_COUNT")
    return dict(causes=dict(out),shape_methods=shape_methods,
                divergent_methods=previous["divergence"],
                unknown_methods=previous["unknown"])

def emit(result):
    need(type(result) is dict and set(result)==
         {"causes","shape_methods","divergent_methods","unknown_methods"},
         "PUBLIC_SCHEMA")
    q=result["causes"]
    need(type(q) is dict and set(q)==set(CAUSES),"PUBLIC_CAUSES")
    n=result["shape_methods"];d=result["divergent_methods"];u=result["unknown_methods"]
    need(all(type(x) is int and 0<=x<=1000000 for x in (n,d,u)) and n<=d,
         "PUBLIC_TOTALS")
    need(all(type(v) is int and 0<=v<=n for v in q.values()) and
         sum(q.values())==n,"PUBLIC_COUNT_RECONCILIATION")
    for c in CAUSES:print("P265_SHAPE_"+c+"="+str(q[c]))
    for label,value in (
      ("SHAPE_METHODS",str(n)),
      ("DIVERGENT_METHODS",str(d)),
      ("UNKNOWN_METHODS",str(u)),
      ("IDENTITIES_AND_OPERAND_VALUES","WITHHELD"),
      ("ENCODING_REPRESENTATION_EQUIVALENCE","NOT_ATTESTED"),
      ("ALL_UNKNOWN_METHODS","NOT_ATTESTED"),
      ("UNCHANGED_P245_GATE","NOT_ATTESTED"),
      ("ART_AND_PROCESS_OWNER","NOT_ATTESTED"),
      ("RELEASE","DENY"),
      ("V139","STRUCTURAL_BLOCKED")):
        print("P265_"+label+"="+value)
    return 2

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P265_SOURCE_ONLY=YES")
        print("P265_REAL_SHAPE_CAUSE=NOT_ATTESTED")
        print("P265_NO_APK_BUILD_INSTALL_OR_RELEASE=YES")
        print("P265_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(report(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P265_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
