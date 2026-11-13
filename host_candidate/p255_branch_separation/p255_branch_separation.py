#!/usr/bin/env python3
"""P255: independently audit explicit if/goto edges vs opcode-layout changes.

P253 conservatively labeled edges DIFFER whenever layout OPCODE_CHANGED or
COUNT_CHANGED. That conflates an opcode mismatch with a proven jump mismatch.
P255 independently compares concrete if/goto source, opcode, destination
ordinal and conditional fallthrough; still NEVER certifies complete normal
CFG, exception safety, legal relocation, ART or production release.
"""
import argparse,re,sys
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import compare_pair,branches,instructions,audit_indexes

def inspect_pair(a,b,da,db):
    previous=compare_pair(a,b,da,db)
    left,right=decode(a,da),decode(b,db)
    ba=branches(instructions(a,left),left[0])
    bb=branches(instructions(b,right),right[0])
    actual=("NONE" if not ba and not bb else
            "ORDINALS_MATCH_ONLY" if ba==bb else "ORDINALS_DIFFER")
    legacy=previous["branches"]
    conflation=(legacy!=actual)
    # P253 may differ from independent concrete edges only because it
    # combines opcode/count mismatches into the old single label.
    if conflation:
        need(legacy=="ORDINALS_DIFFER" and actual=="ORDINALS_MATCH_ONLY"
             and previous["layout"] in ("OPCODE_CHANGED","COUNT_CHANGED"),
             "UNEXPLAINED_LEGACY_DIVERGENCE")
    return dict(layout=previous["layout"],
                explicit_branch=actual,
                legacy_branch_conflated="YES" if conflation else "NO",
                exception_ordinal=previous["exception"],
                size_changed=previous["code_size_changed"])

def audit(original,derived,da,db):
    predecessor=audit_indexes(original,derived,da,db)
    first=None
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        if decode(a,da)[0]!=decode(b,db)[0]:
            first=(a,b)
            break
    if first is None:
        need(predecessor["group"]=="NONE","EXPECTED_NO_SIZE_METHOD")
        return dict(group="NONE",relation=predecessor["relation"],
                    layout="NONE",explicit_branch="NONE",
                    exception_ordinal="NONE",legacy_branch_conflated="NO",
                    size_changed=False)
    check=inspect_pair(first[0],first[1],da,db)
    need(check["layout"]==predecessor["layout"] and
         check["exception_ordinal"]==predecessor["exception"] and
         check["size_changed"],"P253_FIRST_SIZE_PARITY")
    return dict(group=predecessor["group"],
                relation=predecessor["relation"],**check)

def emit(result):
    need(type(result) is dict and
         result.get("group") in {"NONE","START_COROUTINE","OTHER_PRIMARY"} and
         result.get("relation") in {"NOT_APPLICABLE","SAME_METHOD","DIFFERENT_METHOD"} and
         result.get("layout") in {"NONE","SAME_LAYOUT","WIDTH_ONLY","OPCODE_CHANGED","COUNT_CHANGED"} and
         result.get("explicit_branch") in {"NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"} and
         result.get("exception_ordinal") in {"NONE","ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"} and
         result.get("legacy_branch_conflated") in {"YES","NO"},
         "PUBLIC_ENUM")
    need(type(result.get("size_changed")) is bool and
         (result["group"]=="NONE")== (result["layout"]=="NONE")== (not result["size_changed"]),
         "PUBLIC_SIZE_STATE")
    need(result["legacy_branch_conflated"]!="YES" or
         (result["explicit_branch"]=="ORDINALS_MATCH_ONLY" and
          result["layout"] in {"OPCODE_CHANGED","COUNT_CHANGED"}),
         "PUBLIC_CONFLATION_STATE")
    for label,value in (
      ("FIRST_SIZE_GROUP",result["group"]),
      ("FIRST_SIZE_LAYOUT",result["layout"]),
      ("EXPLICIT_IF_GOTO_SIGNATURE",result["explicit_branch"]),
      ("P253_BRANCH_LABEL_CONFLATED",result["legacy_branch_conflated"]),
      ("EXCEPTION_TARGET_ORDINALS",result["exception_ordinal"]),
      ("FIRST_SIZE_VS_EXCEPTION_METHOD",result["relation"]),
      ("COMPLETE_NORMAL_CFG","NOT_ATTESTED"),
      ("OPERAND_SEMANTICS","NOT_ATTESTED"),
      ("LEGAL_RELOCATION","NOT_ATTESTED"),
      ("UNCHANGED_P245_GATE","NOT_ATTESTED"),
      ("ART_PROCESS_ISOLATION","NOT_ATTESTED"),
      ("V139","STRUCTURAL_BLOCKED")):
        print("P255_"+label+"="+value)
    return 2 if result["size_changed"] else 0

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--signed-original",type=Path)
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    a=p.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in args):
        print("P255_SOURCE_ONLY=YES")
        print("P255_REAL_BRANCH_SIGNATURE=NOT_ATTESTED")
        print("P255_NO_APK_BUILD_ADB_OR_RELEASE=YES")
        print("P255_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in args),"PINNED_THREE_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P255_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
