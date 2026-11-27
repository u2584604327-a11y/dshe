#!/usr/bin/env python3
"""P273: sealed, strictly read-only provenance for raw DEX exception table deltas.

Map original try-boundaries and handler targets to candidate instruction ordinals,
then test exact candidate table equality. An exact mapping is *not* bytecode or
ART semantic equivalence. This never bypasses original P245/P209 deny and never
prints private method identities, code offsets, references or registers.
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
from p251_method_relation import ordinal_edges
from p253_cfg_ordinal import instructions, UNSUPPORTED
from p257_opcode_family import encoding_candidate, frame
from p261_all_method_census import explicit_branches, opaque

MAP_CATEGORIES=("EXACT_BOUNDARY_REMAP","MAPPED_TABLE_DIFFER","UNVERIFIED_LAYOUT")
ORDINAL_CATEGORIES=("SAME","DIFFER","UNVERIFIED")
OPCODE_CATEGORIES=("EXACT_OPCODE_NAMES","ENCODING_FAMILY_ONLY",
                   "OPERATION_KIND_CHANGED","INSTRUCTION_COUNT_CHANGED",
                   "OPAQUE_PAYLOAD_UNVERIFIED")
BRANCH_CATEGORIES=("MATCH","DIFFER","UNVERIFIED")
FRAME_CATEGORIES=("MATCH","DIFFER","NOT_ATTESTED")
SHIFT_CATEGORIES=("TRY_START","TRY_END","TYPED_HANDLER_TARGET",
                  "CATCHALL_HANDLER_TARGET","CODE_SIZE")
CLASS_NAMES=("REMAP","ORDINAL","OPCODE","BRANCH","FRAME")
ALL_CLASSES=(MAP_CATEGORIES,ORDINAL_CATEGORIES,OPCODE_CATEGORIES,
             BRANCH_CATEGORIES,FRAME_CATEGORIES)

def private_row_mapping(left,right,ra,rb):
    """Exact index-aligned pc translation, including synthetic end boundary."""
    if len(ra)!=len(rb) or not ra:return None
    total_a,total_b=left[0],right[0]
    pcs_a=[r[0] for r in ra];pcs_b=[r[0] for r in rb]
    need(type(total_a) is int and type(total_b) is int and
         total_a>0 and total_b>0,"TRANSLATION_TOTAL")
    need(pcs_a[0]==pcs_b[0]==0 and
         pcs_a==sorted(set(pcs_a)) and pcs_b==sorted(set(pcs_b)) and
         pcs_a[-1]<total_a and pcs_b[-1]<total_b,"TRANSLATION_BOUNDARIES")
    mapping=dict(zip(pcs_a,pcs_b))
    mapping[total_a]=total_b
    need(len(mapping)==len(ra)+1,"TRANSLATION_MAPPING")
    return mapping

def translated_exception(left,mapping):
    """Fail closed on an original offset with no exact instruction boundary."""
    if mapping is None:return None
    output=[]
    for start, width,(typed,catchall) in left[1]:
        end=start+width
        need(start in mapping and end in mapping and
             mapping[end]>mapping[start],"TRANSLATION_TRY")
        result=[]
        for descriptor,pc in typed:
            need(pc in mapping and pc!=left[0],"TRANSLATION_TYPED_PC")
            result.append((descriptor,mapping[pc]))
        if catchall is not None:
            need(catchall in mapping and catchall!=left[0],
                 "TRANSLATION_CATCHALL_PC")
        newcatch=None if catchall is None else mapping[catchall]
        output.append((mapping[start],mapping[end]-mapping[start],
                       (tuple(result),newcatch)))
    return tuple(output)

def shift_flags(left,right):
    """Anonymous comparison of existing raw fields; no offset emitted."""
    flags={k:False for k in SHIFT_CATEGORIES}
    flags["CODE_SIZE"]=left[0]!=right[0]
    a,b=left[1],right[1]
    for x,y in zip(a,b):
        flags["TRY_START"] |= x[0]!=y[0]
        flags["TRY_END"] |= x[0]+x[1]!=y[0]+y[1]
        old_t,old_c=x[2];new_t,new_c=y[2]
        for e,f in zip(old_t,new_t):
            flags["TYPED_HANDLER_TARGET"] |= e[1]!=f[1]
        if old_c is not None and new_c is not None:
            flags["CATCHALL_HANDLER_TARGET"] |= old_c!=new_c
    return flags

def provenance(left,right,ra,rb,prior_opaque=False,frame_category="MATCH"):
    """Return only labels and booleans; deny-only even on exact remapping."""
    need(first_difference((left[0],left[1]),(left[0],right[1]))!="SAME",
         "RAW_EXCEPTION_DIFFERENCE_REQUIRED")
    need(frame_category in FRAME_CATEGORIES,"FRAME_CATEGORY")
    shifted=shift_flags(left,right)
    if prior_opaque:
        opcode="OPAQUE_PAYLOAD_UNVERIFIED"
    elif len(ra)!=len(rb):
        opcode="INSTRUCTION_COUNT_CHANGED"
    elif all(x[1]==y[1] for x,y in zip(ra,rb)):
        opcode="EXACT_OPCODE_NAMES"
    elif all(x[1]==y[1] or encoding_candidate(x[1],y[1])
             for x,y in zip(ra,rb)):
        opcode="ENCODING_FAMILY_ONLY"
    else:
        opcode="OPERATION_KIND_CHANGED"
    mapping=private_row_mapping(left,right,ra,rb)
    if mapping is None or prior_opaque:
        mapped="UNVERIFIED_LAYOUT"
    else:
        remapped=translated_exception(left,mapping)
        mapped=("EXACT_BOUNDARY_REMAP" if remapped==right[1]
                else "MAPPED_TABLE_DIFFER")
    # Independently recompute descriptor-bearing typed/catch-all ordinals.
    if mapping is None:
        ordinal="UNVERIFIED"
    else:
        ord_a=ordinal_from_rows(left,ra)
        ord_b=ordinal_from_rows(right,rb)
        ordinal="SAME" if ord_a==ord_b else "DIFFER"
    if prior_opaque:
        branch="UNVERIFIED"
    else:
        try:
            x=explicit_branches(ra,left[0])
            y=explicit_branches(rb,right[0])
            branch="MATCH" if x==y else "DIFFER"
        except Exception:
            branch="UNVERIFIED"
    return dict(classes=(mapped,ordinal,opcode,branch,frame_category),
                shifted=shifted)

def ordinal_from_rows(decoded,rows):
    pcs={pc:i for i,(pc,_,_,_) in enumerate(rows)}
    need(len(pcs)==len(rows),"ORDINAL_DUPLICATE")
    pcs[decoded[0]]=len(rows)
    out=[]
    for start,width,(typed,catchall) in decoded[1]:
        end=start+width
        need(start in pcs and end in pcs and pcs[start]<pcs[end],
             "ORDINAL_TRY")
        need(all(pc in pcs and pc!=decoded[0] for _,pc in typed),
             "ORDINAL_TYPED")
        if catchall is not None:
            need(catchall in pcs and catchall!=decoded[0],"ORDINAL_CATCH")
        out.append((pcs[start],pcs[end],
                    tuple((desc,pcs[pc]) for desc,pc in typed),
                    None if catchall is None else pcs[catchall]))
    return tuple(out)

def audit(original,derived,da,db):
    base=dual(original,derived,da,db)
    counts=[Counter({k:0 for k in names}) for names in ALL_CLASSES]
    shifts=Counter({k:0 for k in SHIFT_CATEGORIES})
    raw=0
    no_code=0
    method_count=0
    for key in sorted(original):
        a,b=original[key],derived[key]
        need((a.get_code() is None)==(b.get_code() is None),"CODE_EXISTENCE")
        if a.get_code() is None:
            no_code+=1
            continue
        method_count+=1
        left,right=decode(a,da),decode(b,db)
        if first_difference((left[0],left[1]),(left[0],right[1]))=="SAME":
            continue
        ra,rb=instructions(a,left),instructions(b,right)
        data=provenance(left,right,ra,rb,opaque(a) or opaque(b),frame(a,b))
        for i,name in enumerate(data["classes"]):
            need(name in ALL_CLASSES[i],"CLASS_ENUM")
            counts[i][name]+=1
        for name,value in data["shifted"].items():
            need(name in SHIFT_CATEGORIES and type(value) is bool,"SHIFT_SCHEMA")
            shifts[name]+=int(value)
        # Independently match P251's ordinal classification. A mismatch is fatal.
        if data["classes"][1]!="UNVERIFIED":
            need((data["classes"][1]=="SAME")==
                 (ordinal_edges(a,left)==ordinal_edges(b,right)),
                 "ORDINAL_INDEPENDENT_RECONCILIATION")
        raw+=1
    need(raw>0 and raw<=method_count<=1000000,"RAW_COUNT")
    need((raw>0)==(base["exception_gate"]=="DENY"),"P249_EXCEPTION_GATE")
    need(sum(counts[0].values())==raw,"COVERAGE")
    return dict(counts=[dict(c) for c in counts],shifts=dict(shifts),
                original_code_methods=method_count,raw_exception_methods=raw,
                previous_exception_gate=base["exception_gate"])

def emit(q):
    need(type(q) is dict and set(q)=={"counts","shifts","original_code_methods",
         "raw_exception_methods","previous_exception_gate"},"PUBLIC_SCHEMA")
    n=q["raw_exception_methods"]
    need(type(n) is int and 0<n<=1000000 and
         type(q["original_code_methods"]) is int and n<=q["original_code_methods"]<=1000000,
         "PUBLIC_METHOD_COUNTS")
    need(q["previous_exception_gate"]=="DENY","PRIOR_DENY_REQUIRED")
    need(type(q["counts"]) is list and len(q["counts"])==len(ALL_CLASSES),
         "PUBLIC_COUNT_GROUPS")
    for c,names in zip(q["counts"],ALL_CLASSES):
        need(type(c) is dict and set(c)==set(names),"PUBLIC_GROUP_ENUMS")
        need(all(type(v) is int and 0<=v<=n for v in c.values()) and
             sum(c.values())==n,"PUBLIC_GROUP_COVERAGE")
    need(type(q["shifts"]) is dict and set(q["shifts"])==set(SHIFT_CATEGORIES) and
         all(type(v) is int and 0<=v<=n for v in q["shifts"].values()),
         "PUBLIC_SHIFT_COUNTS")
    for label,items in zip(CLASS_NAMES,q["counts"]):
        for cat,num in items.items():print("P273_"+label+"_"+cat+"="+str(num))
    for cat,num in q["shifts"].items():
        print("P273_RAW_SHIFT_"+cat+"="+str(num))
    print("P273_RAW_EXCEPTION_CHANGED="+str(n))
    print("P273_ORIGINAL_CODE_METHODS="+str(q["original_code_methods"]))
    print("P273_EXISTING_EXCEPTION_GATE=DENY")
    print("P273_BOUNDARY_REMAP_IS_NOT_ART_SEMANTIC_EQUIVALENCE=YES")
    print("P273_P245_FULL_STATIC_PARITY=NOT_ATTESTED")
    print("P273_PRIVATE_METHODS_OFFSETS_TYPES_AND_REGISTERS=WITHHELD")
    print("P273_RELEASE=DENY")
    print("P273_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for label in ("signed-original","base","candidate"):
        p.add_argument("--"+label,type=Path)
    a=p.parse_args()
    paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P273_SOURCE_ONLY=YES")
        print("P273_REAL_EXCEPTION_REMAP=NOT_ATTESTED")
        print("P273_RELEASE=DENY")
        print("P273_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as err:
        code=str(err)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P273_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
