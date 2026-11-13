#!/usr/bin/env python3
"""P275. Read-only all-original-method DEX encoding-width provenance (DENY only).

Counts individual opcode transitions, not just methods containing transitions.
Classifies signed instruction length and, for const-string/jumbo, independently
resolves the ORIGINAL and CANDIDATE DEX string-pool refs without exposing them.
A remapped pool index is not a proven build cause. In particular, this cannot
establish ART semantic parity nor waive original P245 exception rejection.
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
]
from p246_exception_semantics import decode, index, load, need, first_difference
from p249_dual_diff import seal, dual
from p253_cfg_ordinal import instructions
from p257_opcode_family import encoding_candidate, FAMILY_BY_OPCODE
from p261_all_method_census import opaque

TRANSITIONS=(
 "STRING_TO_JUMBO","JUMBO_TO_STRING",
 "GOTO_WIDEN","GOTO_NARROW",
 "MOVE_WIDEN","MOVE_NARROW",
 "INVOKE_TO_RANGE","INVOKE_FROM_RANGE",
 "CONST_WIDEN","CONST_NARROW",
 "CONST_WIDE_WIDEN","CONST_WIDE_NARROW",
 "OTHER_ENCODING_VARIANT","OPERATION_KIND_CHANGED","INVALID_WIDTH_OR_OPCODE",
)
WIDTHS=("POSITIVE","ZERO","NEGATIVE","INVALID")
STRING_REFS=("SAME_STRING_SAME_REGISTER","SAME_STRING_REGISTER_DIFFER",
             "DIFFERENT_STRING","POOL_REFERENCE_UNREADABLE","NOT_APPLICABLE")
JUMBO_INDEX=("JUMBO_REQUIRES_32BIT","JUMBO_FITS_16BIT","UNKNOWN","NOT_APPLICABLE")
METHOD_FIELDS=("ORIGINAL_CODE_METHODS","CODE_SIZE_CHANGED",
               "SUPPORTED_ENCODING_METHODS","OPERATION_KIND_CHANGED_METHODS",
               "OPCODE_COUNT_CHANGED_METHODS","OPAQUE_PAYLOAD_METHODS",
               "SIZE_CHANGED_AND_ENCODING_METHODS","RAW_EXCEPTION_CHANGED",
               "SIZE_CHANGED_WITHOUT_ENCODING_METHODS")

def transition(name_a,name_b,width_a,width_b):
    """Only a fixed anonymous family classification leaves this function."""
    if (type(name_a) is not str or type(name_b) is not str or
        type(width_a) is not int or type(width_b) is not int or
        width_a not in (2,4,6,8,10) or width_b not in (2,4,6,8,10)):
        return ("INVALID_WIDTH_OR_OPCODE","INVALID")
    sign=("POSITIVE" if width_b>width_a else
          "NEGATIVE" if width_b<width_a else "ZERO")
    if name_a==name_b:
        return ("INVALID_WIDTH_OR_OPCODE",sign)
    if not encoding_candidate(name_a,name_b):
        return ("OPERATION_KIND_CHANGED",sign)
    family=FAMILY_BY_OPCODE[name_a]
    if family=="const-string":
        if name_a=="const-string" and name_b=="const-string/jumbo" and (width_a,width_b)==(4,6):
            return ("STRING_TO_JUMBO",sign)
        if name_a=="const-string/jumbo" and name_b=="const-string" and (width_a,width_b)==(6,4):
            return ("JUMBO_TO_STRING",sign)
        return ("INVALID_WIDTH_OR_OPCODE",sign)
    if family=="goto":
        expected={"goto":2,"goto/16":4,"goto/32":6}
        if expected.get(name_a)!=width_a or expected.get(name_b)!=width_b or sign=="ZERO":
            return ("INVALID_WIDTH_OR_OPCODE",sign)
        return ("GOTO_WIDEN" if sign=="POSITIVE" else "GOTO_NARROW",sign)
    if family in ("move","move-wide","move-object"):
        expected={family:2,family+"/from16":4,family+"/16":6}
        if expected.get(name_a)!=width_a or expected.get(name_b)!=width_b or sign=="ZERO":
            return ("INVALID_WIDTH_OR_OPCODE",sign)
        return ("MOVE_WIDEN" if sign=="POSITIVE" else "MOVE_NARROW",sign)
    if family.startswith("invoke-"):
        if (width_a,width_b)!=(6,6):
            return ("INVALID_WIDTH_OR_OPCODE",sign)
        return ("INVOKE_TO_RANGE" if name_b.endswith("/range")
                else "INVOKE_FROM_RANGE",sign)
    if family in ("const","const-wide"):
        if sign=="ZERO":
            return ("OTHER_ENCODING_VARIANT",sign)
        prefix="CONST_WIDE" if family=="const-wide" else "CONST"
        return (prefix+"_WIDEN" if sign=="POSITIVE" else prefix+"_NARROW",sign)
    return ("OTHER_ENCODING_VARIANT",sign)

def string_index(ins,name):
    """Read exact 21c/31c raw byte encoding; return (register, pool index) only."""
    if name not in ("const-string","const-string/jumbo"):
        return None
    getter=getattr(ins,"get_raw",None)
    if not callable(getter):
        return None
    try: raw=getter()
    except Exception:return None
    if not isinstance(raw,(bytes,bytearray)):
        return None
    if name=="const-string":
        if len(raw)!=4 or raw[0]!=0x1a:return None
    else:
        if len(raw)!=6 or raw[0]!=0x1b:return None
    return (raw[1],int.from_bytes(raw[2:],"little"))

def pool_string(dex,index_value):
    getter=getattr(dex,"get_cm_string",None)
    if not callable(getter) or type(index_value) is not int or index_value<0:
        return None
    try:value=getter(index_value)
    except Exception:return None
    if not isinstance(value,str) or len(value)>1000000:return None
    return value

def compare_string_refs(x,y,da,db):
    """Independent content and register comparison; only bounded labels returned."""
    names=(x[1],y[1])
    if set(names)!={"const-string","const-string/jumbo"}:
        return ("NOT_APPLICABLE","NOT_APPLICABLE")
    a=string_index(x[3],names[0]);b=string_index(y[3],names[1])
    if a is None or b is None:
        return ("POOL_REFERENCE_UNREADABLE","UNKNOWN")
    jumbo_i=(a[1] if names[0].endswith("/jumbo") else b[1])
    index_cat=("JUMBO_REQUIRES_32BIT" if jumbo_i>65535
               else "JUMBO_FITS_16BIT")
    va,vb=pool_string(da,a[1]),pool_string(db,b[1])
    if va is None or vb is None:
        return ("POOL_REFERENCE_UNREADABLE",index_cat)
    if va!=vb:return ("DIFFERENT_STRING",index_cat)
    return (("SAME_STRING_SAME_REGISTER" if a[0]==b[0]
             else "SAME_STRING_REGISTER_DIFFER"),index_cat)

def audit(original,derived,da,db):
    previous=dual(original,derived,da,db)
    tally=Counter({name:0 for name in METHOD_FIELDS})
    transitions=Counter({name:0 for name in TRANSITIONS})
    signs=Counter({name:0 for name in WIDTHS})
    refs=Counter({name:0 for name in STRING_REFS})
    jumbo=Counter({name:0 for name in JUMBO_INDEX})
    for key in sorted(original):
        a,b=original[key],derived[key]
        need((a.get_code() is None)==(b.get_code() is None),"METHOD_CODE_SET")
        if a.get_code() is None:continue
        tally["ORIGINAL_CODE_METHODS"]+=1
        left,right=decode(a,da),decode(b,db)
        size_diff=left[0]!=right[0]
        raw=first_difference((left[0],left[1]),(left[0],right[1]))!="SAME"
        tally["CODE_SIZE_CHANGED"]+=int(size_diff)
        tally["RAW_EXCEPTION_CHANGED"]+=int(raw)
        if opaque(a) or opaque(b):
            tally["OPAQUE_PAYLOAD_METHODS"]+=1
            if size_diff:tally["SIZE_CHANGED_WITHOUT_ENCODING_METHODS"]+=1
            continue
        ra,rb=instructions(a,left),instructions(b,right)
        if len(ra)!=len(rb):
            tally["OPCODE_COUNT_CHANGED_METHODS"]+=1
            if size_diff:tally["SIZE_CHANGED_WITHOUT_ENCODING_METHODS"]+=1
            continue
        changes=[(x,y) for x,y in zip(ra,rb) if x[1]!=y[1]]
        family=bool(changes) and all(encoding_candidate(x[1],y[1]) for x,y in changes)
        tally["SUPPORTED_ENCODING_METHODS"]+=int(family)
        tally["OPERATION_KIND_CHANGED_METHODS"]+=int(bool(changes) and not family)
        tally["SIZE_CHANGED_AND_ENCODING_METHODS"]+=int(size_diff and family)
        tally["SIZE_CHANGED_WITHOUT_ENCODING_METHODS"]+=int(size_diff and not family)
        for x,y in changes:
            category,sign=transition(x[1],y[1],x[2],y[2])
            need(category in TRANSITIONS and sign in WIDTHS,"DIRECTION_CATEGORY")
            transitions[category]+=1
            signs[sign]+=1
            if category in ("STRING_TO_JUMBO","JUMBO_TO_STRING"):
                ref_cat,index_cat=compare_string_refs(x,y,da,db)
            else:
                ref_cat,index_cat="NOT_APPLICABLE","NOT_APPLICABLE"
            need(ref_cat in STRING_REFS and index_cat in JUMBO_INDEX,"REF_CATEGORY")
            refs[ref_cat]+=1;jumbo[index_cat]+=1
    need(tally["ORIGINAL_CODE_METHODS"]>0,"NO_ORIGINAL_METHOD")
    need(tally["CODE_SIZE_CHANGED"]==tally["SIZE_CHANGED_AND_ENCODING_METHODS"]+
         tally["SIZE_CHANGED_WITHOUT_ENCODING_METHODS"],"SIZE_METHOD_COVERAGE")
    need((tally["CODE_SIZE_CHANGED"]>0)==(previous["code_gate"]=="DENY"),
         "P249_CODE_GATE")
    need((tally["RAW_EXCEPTION_CHANGED"]>0)==(previous["exception_gate"]=="DENY"),
         "P249_EXCEPTION_GATE")
    need(sum(transitions.values())==sum(signs.values())==
         sum(refs.values())==sum(jumbo.values()),"CHANGED_INSTRUCTION_COVERAGE")
    return dict(methods=dict(tally),transitions=dict(transitions),
                widths=dict(signs),strings=dict(refs),jumbo=dict(jumbo),
                code_gate=previous["code_gate"],
                exception_gate=previous["exception_gate"])

def emit(q):
    required=("methods","transitions","widths","strings","jumbo",
              "code_gate","exception_gate")
    need(type(q) is dict and set(q)==set(required),"PUBLIC_SCHEMA")
    groups=((q["methods"],METHOD_FIELDS),(q["transitions"],TRANSITIONS),
            (q["widths"],WIDTHS),(q["strings"],STRING_REFS),
            (q["jumbo"],JUMBO_INDEX))
    need(q["code_gate"]=="DENY" and q["exception_gate"]=="DENY","DENY_REQUIRED")
    for group,names in groups:
        need(type(group) is dict and set(group)==set(names),"PUBLIC_ENUMS")
        need(all(type(v) is int and 0<=v<=1000000 for v in group.values()),
             "PUBLIC_COUNT_RANGE")
    n=q["methods"]["ORIGINAL_CODE_METHODS"]
    need(0<n<=1000000 and
         q["methods"]["CODE_SIZE_CHANGED"]==(
         q["methods"]["SIZE_CHANGED_AND_ENCODING_METHODS"]+
         q["methods"]["SIZE_CHANGED_WITHOUT_ENCODING_METHODS"]),
         "SIZE_COVERAGE")
    changes=sum(q["transitions"].values())
    need(changes==sum(q["widths"].values())==sum(q["strings"].values())==
         sum(q["jumbo"].values()),"TRANSITION_COVERAGE")
    for prefix,part in zip(("METHOD","TRANSITION","WIDTH","STRING","JUMBO"),
                           (q["methods"],q["transitions"],q["widths"],
                            q["strings"],q["jumbo"])):
        for category,count in part.items():
            print("P275_"+prefix+"_"+category+"="+str(count))
    print("P275_P249_CODE_GATE=DENY")
    print("P275_P249_EXCEPTION_GATE=DENY")
    print("P275_WIDTH_OR_POOL_INDEX_IS_NOT_SEMANTIC_PARITY=YES")
    print("P275_POOL_INDEX_CAUSALITY=NOT_ATTESTED")
    print("P275_PRIVATE_METHODS_STRINGS_REFERENCES_AND_PCS=WITHHELD")
    print("P275_RELEASE=DENY")
    print("P275_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for label in ("signed-original","base","candidate"):
        p.add_argument("--"+label,type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(v is None for v in paths):
        print("P275_SOURCE_ONLY=YES")
        print("P275_REAL_ENCODING_WIDTH_CENSUS=NOT_ATTESTED")
        print("P275_RELEASE=DENY")
        print("P275_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P275_DENY_UNEXPECTED"
        print(code,file=sys.stderr);return 2

if __name__=="__main__":
    raise SystemExit(main())
