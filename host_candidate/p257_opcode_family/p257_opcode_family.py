#!/usr/bin/env python3
"""P257 read-only first-size method opcode-family and operand audit.

Encoding-family equality is a *candidate* classification, never an assertion
that register/literal/index operands, instructions, CFG or ART are equivalent.
No original method/operand/string/PC is printed. Unknown operands fail closed.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
             "host_candidate/p249_dual_diff",
             "host_candidate/p251_method_relation",
             "host_candidate/p253_cfg_ordinal",
             "host_candidate/p255_branch_separation"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p255_branch_separation import audit as p255_audit

# Explicit, narrow DEX variant families. Only candidate classification:
# each expanded encoding still requires independently verified operands.
FAMILIES={
 "move":("move","move/from16","move/16"),
 "move-wide":("move-wide","move-wide/from16","move-wide/16"),
 "move-object":("move-object","move-object/from16","move-object/16"),
 "const":("const/4","const/16","const","const/high16"),
 "const-wide":("const-wide/16","const-wide/32","const-wide","const-wide/high16"),
 "const-string":("const-string","const-string/jumbo"),
 "goto":("goto","goto/16","goto/32"),
}
for family in ("virtual","super","direct","static","interface"):
    key="invoke-"+family
    FAMILIES[key]=(key,key+"/range")
FAMILY_BY_OPCODE={name:group for group,names in FAMILIES.items() for name in names}
FIRST=frozenset(("NONE","COUNT_CHANGED","ENCODING_FAMILY_CANDIDATE","OPERATION_KIND_CHANGED"))
ALL=frozenset(("NONE","COUNT_CHANGED","ONLY_ENCODING_CANDIDATES","HAS_OPERATION_KIND_CHANGE"))
OPERANDS=frozenset(("NOT_APPLICABLE","NOT_ATTESTED","STRUCTURED_MATCH","STRUCTURED_DIFFER",
                    "BRANCH_TARGETS_DELEGATED"))
REGISTER_FRAME=frozenset(("MATCH","DIFFER","NOT_ATTESTED"))

def encoding_candidate(old,new):
    """Explicit names only; never generalize via a shared string prefix."""
    a,b=FAMILY_BY_OPCODE.get(old),FAMILY_BY_OPCODE.get(new)
    return a is not None and a==b and old!=new

def frame(a,b):
    attrs=("get_registers_size","get_ins_size","get_outs_size")
    try:
        x=tuple(getattr(a.get_code(),f)() for f in attrs)
        y=tuple(getattr(b.get_code(),f)() for f in attrs)
    except (AttributeError,TypeError,ValueError):
        return "NOT_ATTESTED"
    need(all(type(v) is int and 0<=v<=65535 for v in x+y),"REGISTER_FRAME_VALUE")
    return "MATCH" if x==y else "DIFFER"

def normalized_operands(inst):
    """Strict subset of Androguard Operand tuples, in *private* memory.

    REGISTER=0, LITERAL=1, OFFSET=3, KIND flags include 0x100.
    No raw constant pool index is accepted as semantic reference parity;
    KIND requires the resolved third item to compare across pool remapping.
    Unsupported operands return None => NOT_ATTESTED, never PASS.
    """
    getter=getattr(inst,"get_operands",None)
    if not callable(getter):return None
    try:values=getter()
    except (Exception,):
        return None
    if not isinstance(values,(tuple,list)) or len(values)>256:return None
    result=[]
    for item in values:
        if not isinstance(item,(tuple,list)) or len(item)<2:return None
        tag,value=item[0],item[1]
        if not isinstance(tag,int) or type(value) is not int:return None
        if tag==0 and len(item)==2 and 0<=value<=65535:
            result.append(("R",value))
        elif tag==1 and len(item)==2 and -(1<<63)<=value<(1<<64):
            result.append(("L",value))
        elif tag>=256 and tag<512 and len(item)==3 and value>=0:
            resolved=item[2]
            if not isinstance(resolved,str) or not resolved or len(resolved)>8192:
                return None
            result.append(("K",tag,resolved))
        else:
            # Raw offsets and unsupported formats never yield operand parity.
            return None
    return tuple(result)

def signature(a,b,old_opcode,new_opcode):
    if (FAMILY_BY_OPCODE.get(old_opcode)=="goto" and
        FAMILY_BY_OPCODE.get(new_opcode)=="goto"):
        return "BRANCH_TARGETS_DELEGATED"
    x,y=normalized_operands(a),normalized_operands(b)
    if x is None or y is None:return "NOT_ATTESTED"
    return "STRUCTURED_MATCH" if x==y else "STRUCTURED_DIFFER"

def inspect_pair(a,b,da,db):
    left,right=decode(a,da),decode(b,db)
    ra,rb=instructions(a,left),instructions(b,right)
    result={"frame":frame(a,b)}
    if len(ra)!=len(rb):
        result.update(first="COUNT_CHANGED",all="COUNT_CHANGED",
                      operands="NOT_APPLICABLE")
        return result
    differences=[(x,y) for x,y in zip(ra,rb) if x[1]!=y[1]]
    if not differences:
        result.update(first="NONE",all="NONE",operands="NOT_APPLICABLE")
        return result
    x,y=differences[0]
    result["first"]=("ENCODING_FAMILY_CANDIDATE" if encoding_candidate(x[1],y[1])
                     else "OPERATION_KIND_CHANGED")
    result["all"]=("ONLY_ENCODING_CANDIDATES" if all(
        encoding_candidate(l[1],r[1]) for l,r in differences)
        else "HAS_OPERATION_KIND_CHANGE")
    result["operands"]=signature(x[3],y[3],x[1],y[1])
    return result

def audit(original,derived,da,db):
    previous=p255_audit(original,derived,da,db)
    first=None
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        if decode(a,da)[0]!=decode(b,db)[0]:
            first=(a,b)
            break
    if first is None:
        need(previous["group"]=="NONE","P255_NO_FIRST_METHOD")
        return dict(group="NONE",layout="NONE",relation=previous["relation"],
                    explicit_branch="NONE",exception=previous["exception_ordinal"],
                    size_changed=False,first="NONE",all="NONE",
                    operands="NOT_APPLICABLE",frame="NOT_ATTESTED")
    detail=inspect_pair(first[0],first[1],da,db)
    need(previous["layout"]=="COUNT_CHANGED" and detail["first"]=="COUNT_CHANGED" or
         previous["layout"]!="COUNT_CHANGED" and detail["first"]!="COUNT_CHANGED",
         "LAYOUT_PARITY")
    return dict(group=previous["group"],layout=previous["layout"],
                relation=previous["relation"],explicit_branch=previous["explicit_branch"],
                exception=previous["exception_ordinal"],size_changed=True,**detail)

def emit(q):
    need(type(q) is dict and
         q.get("group") in {"NONE","START_COROUTINE","OTHER_PRIMARY"} and
         q.get("layout") in {"NONE","SAME_LAYOUT","WIDTH_ONLY","OPCODE_CHANGED","COUNT_CHANGED"} and
         q.get("relation") in {"NOT_APPLICABLE","SAME_METHOD","DIFFERENT_METHOD"} and
         q.get("explicit_branch") in {"NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"} and
         q.get("exception") in {"NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"} and
         q.get("first") in FIRST and q.get("all") in ALL and
         q.get("operands") in OPERANDS and q.get("frame") in REGISTER_FRAME,
         "PUBLIC_FIXED_ENUMS")
    need(type(q.get("size_changed")) is bool and
         (q["group"]=="NONE")== (not q["size_changed"]),"PUBLIC_SIZE")
    need((q["first"]=="COUNT_CHANGED")== (q["all"]=="COUNT_CHANGED")==
         (q["layout"]=="COUNT_CHANGED"),"PUBLIC_COUNT")
    need((q["first"]=="NONE")== (q["all"]=="NONE"),"PUBLIC_NONE")
    need(q["first"]!="NONE" or q["operands"]=="NOT_APPLICABLE","PUBLIC_NO_OPCODE")
    need(q["first"]!="COUNT_CHANGED" or q["operands"]=="NOT_APPLICABLE",
         "PUBLIC_COUNT_OPERANDS")
    for label,value in (
        ("FIRST_SIZE_GROUP",q["group"]),
        ("FIRST_SIZE_LAYOUT",q["layout"]),
        ("FIRST_OPCODE_PAIR_CLASS",q["first"]),
        ("ALL_OPCODE_CHANGES_CLASS",q["all"]),
        ("FIRST_PAIR_OPERANDS",q["operands"]),
        ("REGISTER_FRAME",q["frame"]),
        ("EXPLICIT_IF_GOTO_ORDINALS",q["explicit_branch"]),
        ("EXCEPTION_EDGE_ORDINALS",q["exception"]),
        ("FIRST_SIZE_VS_EXCEPTION_METHOD",q["relation"]),
        ("ALL_INSTRUCTION_OPERANDS","NOT_ATTESTED"),
        ("OPCODE_SEMANTIC_EQUIVALENCE","NOT_ATTESTED"),
        ("LEGAL_RELOCATION","NOT_ATTESTED"),
        ("UNCHANGED_P245_FULL_GATE","NOT_ATTESTED"),
        ("ART_AND_PROCESS_OWNER","NOT_ATTESTED"),
        ("V139","STRUCTURAL_BLOCKED")):
        print("P257_"+label+"="+value)
    return 2 if q["size_changed"] else 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in args):
        print("P257_SOURCE_ONLY=YES")
        print("P257_REAL_OPCODE_FAMILY=NOT_ATTESTED")
        print("P257_NO_APK_BUILD_ADB_OR_RELEASE=YES")
        print("P257_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in args),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        msg=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",msg):
            msg="P257_DENY_UNEXPECTED"
        print(msg,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
