#!/usr/bin/env python3
"""P259 strict read-only whole-method operand coverage of first size mismatch.

Only recognized instruction forms/structured operands are compared. Ordinary
branch relative offset is replaced by P255-verified source/target ordinal
edges, but its register operands are still compared. Missing, unsupported or
unresolved operands yield NOT_ATTESTED, not match. This is never release proof.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions,branches
from p257_opcode_family import encoding_candidate,frame,audit as p257_audit

STATES=frozenset(("NOT_APPLICABLE","STRUCTURED_MATCH","STRUCTURED_DIFFER","NOT_ATTESTED","COUNT_CHANGED"))
SIGNATURE=frozenset(("NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"))
BRANCH_NAMES=frozenset(("goto","goto/16","goto/32",
  "if-eq","if-ne","if-lt","if-ge","if-gt","if-le",
  "if-eqz","if-nez","if-ltz","if-gez","if-gtz","if-lez"))
def operands(ins,name):
    """Typed registers/literals/resolved pool references; no raw pool identity.

    A branch must have exactly one OFFSET operand. Its value is NEVER used to
    claim operand parity: all target semantics are compared by P255 branches.
    Comparisons retain all non-offset branch registers; unknown tags deny.
    """
    getter=getattr(ins,"get_operands",None)
    if not callable(getter):return None
    try:items=getter()
    except Exception:return None
    if not isinstance(items,(tuple,list)) or len(items)>256:return None
    normalized=[]
    offsets=0
    for item in items:
        if not isinstance(item,(tuple,list)) or len(item)<2:return None
        tag,val=item[:2]
        if not isinstance(tag,int) or type(val) is not int:return None
        if tag==0 and len(item)==2 and 0<=val<=65535:
            normalized.append(("R",val))
        elif tag==1 and len(item)==2 and -(1<<63)<=val<(1<<64):
            normalized.append(("L",val))
        elif tag==3 and len(item)==2 and name in BRANCH_NAMES:
            offsets+=1
        elif 256<=tag<512 and len(item)==3 and val>=0:
            ref=item[2]
            if not isinstance(ref,str) or not ref or len(ref)>8192:return None
            normalized.append(("K",tag,ref))
        else:
            return None
    if name in BRANCH_NAMES and offsets!=1:return None
    if name not in BRANCH_NAMES and offsets:return None
    return tuple(normalized)

def pair(a,b):
    old,new=a[1],b[1]
    if old!=new and not encoding_candidate(old,new):
        return "STRUCTURED_DIFFER"
    xa,xb=operands(a[3],old),operands(b[3],new)
    if xa is None or xb is None:return "NOT_ATTESTED"
    return "STRUCTURED_MATCH" if xa==xb else "STRUCTURED_DIFFER"

def aggregate(states):
    if not states:return "NOT_APPLICABLE"
    if "STRUCTURED_DIFFER" in states:return "STRUCTURED_DIFFER"
    if "NOT_ATTESTED" in states:return "NOT_ATTESTED"
    need(all(x=="STRUCTURED_MATCH" for x in states),"AGGREGATE_INCONSISTENT")
    return "STRUCTURED_MATCH"

def inspect_pair(a,b,da,db):
    la,lb=decode(a,da),decode(b,db)
    old,new=instructions(a,la),instructions(b,lb)
    result={"frame":frame(a,b)}
    if len(old)!=len(new):
        return dict(total="COUNT_CHANGED",unchanged="COUNT_CHANGED",
                    changed="COUNT_CHANGED",**result)
    # The instruction-pair list is complete; unchanged-opcode instructions
    # are intentionally included and cannot hide a changed literal/register.
    unchanged=[]
    changed=[]
    for x,y in zip(old,new):
        status=pair(x,y)
        (unchanged if x[1]==y[1] else changed).append(status)
    return dict(total=aggregate(unchanged+changed),
                unchanged=aggregate(unchanged),
                changed=aggregate(changed),**result)

def audit(original,derived,da,db):
    previous=p257_audit(original,derived,da,db)
    first=None
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        if decode(a,da)[0]!=decode(b,db)[0]:
            first=(a,b)
            break
    if first is None:
        need(previous["group"]=="NONE","FIRST_SIZE_NONE")
        return dict(group="NONE",layout="NONE",relation=previous["relation"],
                    explicit_branch=previous["explicit_branch"],exception=previous["exception"],
                    opcode_family=previous["all"],size_changed=False,
                    total="NOT_APPLICABLE",unchanged="NOT_APPLICABLE",
                    changed="NOT_APPLICABLE",frame="NOT_ATTESTED")
    detail=inspect_pair(first[0],first[1],da,db)
    need((previous["layout"]=="COUNT_CHANGED")== (detail["total"]=="COUNT_CHANGED"),
         "P257_COUNT_PARITY")
    # P255's independent branch signature and exception ordinal outcome
    # are carried forward, not recomputed as broad CFG semantic proof.
    return dict(group=previous["group"],layout=previous["layout"],
                relation=previous["relation"],explicit_branch=previous["explicit_branch"],
                exception=previous["exception"],opcode_family=previous["all"],
                size_changed=True,**detail)

def emit(q):
    need(type(q) is dict and
         q.get("group") in {"NONE","START_COROUTINE","OTHER_PRIMARY"} and
         q.get("layout") in {"NONE","SAME_LAYOUT","WIDTH_ONLY","OPCODE_CHANGED","COUNT_CHANGED"} and
         q.get("opcode_family") in {"NONE","COUNT_CHANGED","ONLY_ENCODING_CANDIDATES","HAS_OPERATION_KIND_CHANGE"} and
         q.get("relation") in {"NOT_APPLICABLE","SAME_METHOD","DIFFERENT_METHOD"} and
         q.get("explicit_branch") in SIGNATURE and q.get("exception") in SIGNATURE and
         q.get("total") in STATES and q.get("unchanged") in STATES and
         q.get("changed") in STATES and
         q.get("frame") in {"MATCH","DIFFER","NOT_ATTESTED"},"PUBLIC_FIXED_ENUM")
    need(type(q.get("size_changed")) is bool and
         (q["group"]=="NONE")== (not q["size_changed"]),"PUBLIC_SIZE")
    need((q["layout"]=="COUNT_CHANGED")== (q["total"]=="COUNT_CHANGED")==
         (q["unchanged"]=="COUNT_CHANGED")== (q["changed"]=="COUNT_CHANGED"),
         "PUBLIC_COUNT")
    need(q["group"]!="NONE" or
         (q["total"]=="NOT_APPLICABLE" and q["unchanged"]=="NOT_APPLICABLE" and q["changed"]=="NOT_APPLICABLE"),
         "PUBLIC_NOSIZE")
    for name,value in (
      ("FIRST_SIZE_GROUP",q["group"]),
      ("FIRST_SIZE_LAYOUT",q["layout"]),
      ("ALL_OPCODE_FAMILIES",q["opcode_family"]),
      ("ALL_INSTRUCTION_OPERANDS",q["total"]),
      ("UNCHANGED_OPCODE_OPERANDS",q["unchanged"]),
      ("CHANGED_OPCODE_OPERANDS",q["changed"]),
      ("REGISTER_FRAME",q["frame"]),
      ("EXPLICIT_IF_GOTO_ORDINALS",q["explicit_branch"]),
      ("EXCEPTION_EDGE_ORDINALS",q["exception"]),
      ("FIRST_SIZE_VS_EXCEPTION_METHOD",q["relation"]),
      ("SCOPE","FIRST_SIZE_METHOD_ONLY"),
      ("ALL_OTHER_ORIGINAL_METHODS","NOT_ATTESTED"),
      ("OPCODE_SEMANTIC_EQUIVALENCE","NOT_ATTESTED"),
      ("LEGAL_RELOCATION","NOT_ATTESTED"),
      ("UNCHANGED_P245_FULL_GATE","NOT_ATTESTED"),
      ("ART_AND_PROCESS_OWNER","NOT_ATTESTED"),
      ("V139","STRUCTURAL_BLOCKED")):
        print("P259_"+name+"="+value)
    # A method with any changed size is a hard DENY regardless of operands.
    return 2 if q["size_changed"] else 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(v is None for v in args):
        print("P259_SOURCE_ONLY=YES")
        print("P259_REAL_ALL_OPERANDS=NOT_ATTESTED")
        print("P259_NO_APK_BUILD_INSTALL_OR_RELEASE=YES")
        print("P259_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in args),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P259_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
