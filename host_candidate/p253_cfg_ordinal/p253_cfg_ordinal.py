#!/usr/bin/env python3
"""P253 read-only first-code-size method CFG / exception ordinal classifier.

Instruction ordinals are *not* executable equivalence. An exact opcode list and
matching branch/exception ordinal graph cannot prove operands, ART, runtime
ownership, or legal relocation. Unknown switch/payload semantics fail closed.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff","host_candidate/p251_method_relation"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal,START
from p251_method_relation import classify as p251_classify,ordinal_edges

UNSUPPORTED=frozenset(("packed-switch","sparse-switch","fill-array-data",
  "packed-switch-payload","sparse-switch-payload","fill-array-data-payload"))
LAYOUT=frozenset(("NONE","SAME_LAYOUT","WIDTH_ONLY","OPCODE_CHANGED","COUNT_CHANGED"))
CHECK=frozenset(("NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"))
GROUP=frozenset(("NONE","START_COROUTINE","OTHER_PRIMARY"))

def instructions(method, decoded):
    """P246 decode must have checked all byte/code-unit boundaries first."""
    total=decoded[0]
    result=[]
    offset=0
    for pc,ins in method.get_instructions_idx():
        need(type(pc) is int and pc==offset and pc%2==0,"INSTRUCTION_BOUNDARY")
        name=ins.get_name()
        width=ins.get_length()
        need(type(name) is str and re.fullmatch(r"[a-z0-9_/-]+",name),
             "OPCODE_NAME")
        need(type(width) is int and width>0 and width%2==0,"WIDTH")
        # Payloads have additional data-dependent branch semantics that this
        # narrow ordinal classifier deliberately refuses to certify.
        need(name not in UNSUPPORTED and not name.endswith("-payload"),
             "UNSUPPORTED_SWITCH_OR_PAYLOAD")
        result.append((pc//2,name,width,ins))
        offset+=width
    need(result and offset==total*2,"INSTRUCTION_COVERAGE")
    return result

def branches(rows,total):
    """Return explicit ordinary if/goto edges in instruction ordinal space.

    Includes conditional fallthrough. No switch/payload edge is silently
    omitted. A target into a multi-unit instruction body is a hard DENY.
    """
    pc_to_ordinal={pc:i for i,(pc,_,_,_) in enumerate(rows)}
    need(len(pc_to_ordinal)==len(rows),"DUPLICATE_PC")
    edges=[]
    for i,(pc,name,_,ins) in enumerate(rows):
        conditional=name.startswith("if-")
        jumping=name in ("goto","goto/16","goto/32")
        if not conditional and not jumping:continue
        need((not conditional or re.fullmatch(r"if-(?:eq|ne|lt|ge|gt|le|eqz|nez|ltz|gez|gtz|lez)",name) is not None),
             "UNSUPPORTED_IF")
        need(hasattr(ins,"get_ref_off"),"BRANCH_OFFSET_MISSING")
        delta=ins.get_ref_off()
        need(type(delta) is int,"BRANCH_OFFSET_NONINTEGER")
        dest=pc+delta  # both values measured in DEX 16-bit code units
        need(dest in pc_to_ordinal and 0<=dest<total,"BRANCH_TARGET_BOUNDARY")
        if conditional:
            need(i+1<len(rows),"IF_FALLTHROUGH_BOUNDARY")
            edges.append((i,name,pc_to_ordinal[dest],i+1))
        else:
            edges.append((i,name,pc_to_ordinal[dest],None))
    return tuple(edges)

def compare_pair(a,b,da,db):
    """Self-validate both sides; output fixed categories only."""
    left,right=decode(a,da),decode(b,db)
    ra,rb=instructions(a,left),instructions(b,right)
    if len(ra)!=len(rb):layout="COUNT_CHANGED"
    elif tuple(r[1] for r in ra)!=tuple(r[1] for r in rb):layout="OPCODE_CHANGED"
    elif tuple(r[2] for r in ra)!=tuple(r[2] for r in rb):layout="WIDTH_ONLY"
    else:layout="SAME_LAYOUT"
    # Independently parse/validate every branch (even if lists differ).
    ba,bb=branches(ra,left[0]),branches(rb,right[0])
    ea,eb=ordinal_edges(a,left),ordinal_edges(b,right)
    branch=("NONE" if not ba and not bb else
            "ORDINALS_MATCH_ONLY" if ba==bb and layout not in
             ("COUNT_CHANGED","OPCODE_CHANGED") else "ORDINALS_DIFFER")
    exception=("NONE" if not ea and not eb else
               "ORDINALS_MATCH_ONLY" if ea==eb else "ORDINALS_DIFFER")
    return dict(layout=layout,branches=branch,exception=exception,
                code_size_changed=left[0]!=right[0])

def audit_indexes(original,derived,da,db):
    prior=p251_classify(original,derived,da,db)
    first=None
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        left,right=decode(a,da),decode(b,db)
        if left[0]!=right[0]:
            first=(key,a,b)
            break
    group="NONE" if first is None else "START_COROUTINE" if first[0]==START else "OTHER_PRIMARY"
    need(group==prior["size_group"],"P251_FIRST_SIZE_GROUP")
    if first is None:
        return dict(group="NONE",layout="NONE",branches="NONE",exception="NONE",
                    code_size_changed=False,relation=prior["relation"])
    comparison=compare_pair(first[1],first[2],da,db)
    need(comparison["code_size_changed"],"FIRST_SIZE_CHANGED")
    return dict(group=group,relation=prior["relation"],**comparison)

def emit(q):
    need(type(q) is dict and q.get("group") in GROUP and
         q.get("layout") in LAYOUT and
         q.get("branches") in CHECK and q.get("exception") in CHECK and
         q.get("relation") in {"NOT_APPLICABLE","SAME_METHOD","DIFFERENT_METHOD"},
         "PUBLIC_ENUMS")
    need(type(q.get("code_size_changed")) is bool,"PUBLIC_BOOLEAN")
    need((q["group"]=="NONE")== (q["layout"]=="NONE")== (not q["code_size_changed"]),
         "PUBLIC_SIZE_STATE")
    for label,value in (
       ("FIRST_SIZE_GROUP",q["group"]),
       ("FIRST_SIZE_LAYOUT_CLASS",q["layout"]),
       ("FIRST_SIZE_NORMAL_BRANCH_ORDINALS",q["branches"]),
       ("FIRST_SIZE_EXCEPTION_ORDINALS",q["exception"]),
       ("FIRST_SIZE_VS_EXCEPTION_METHOD",q["relation"]),
       ("NORMAL_OPERANDS_AND_PAYLOADS","NOT_ATTESTED"),
       ("LEGAL_RELOCATION","NOT_ATTESTED"),
       ("ORIGINAL_P245_FULL_STATIC","NOT_ATTESTED"),
       ("ANDROID_ART_AND_PROCESS_OWNER","NOT_ATTESTED"),
       ("V139","STRUCTURAL_BLOCKED")):
        print("P253_"+label+"="+value)
    return 2 if q["code_size_changed"] else 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in args):
        print("P253_SOURCE_ONLY=YES")
        print("P253_REAL_FIRST_SIZE_CFG=NOT_ATTESTED")
        print("P253_NO_APK_BUILD_INSTALL_OR_RELEASE=YES")
        print("P253_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in args),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit_indexes(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P253_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
