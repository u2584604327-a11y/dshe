#!/usr/bin/env python3
"""P297: read-only raw invoke method-pool references for P263 unknown methods.

This deliberately covers only DEX 35c/3rc *method* invokes, never assumes
that no invoke means no references, and never attests register/call semantics.
No DEX symbol, identifier, ordinal, raw bytes or reference value is printed.
"""
import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path[:0] = [
    "host_candidate/p246_exception_semantics",
    "host_candidate/p249_dual_diff",
    "host_candidate/p251_method_relation",
    "host_candidate/p253_cfg_ordinal",
    "host_candidate/p255_branch_separation",
    "host_candidate/p257_opcode_family",
    "host_candidate/p259_all_operands",
    "host_candidate/p261_all_method_census",
    "host_candidate/p263_operand_correlation",
    "host_candidate/p265_operand_shape",
    "host_candidate/p267_invoke_words",
    "host_candidate/p269_method_pool",
    "host_candidate/p295_raw_unknowns",
    "host_candidate/p296_instruction_shape",
]
from p246_exception_semantics import load, need, index
from p249_dual_diff import seal
from p269_method_pool import method_pool
from p263_operand_correlation import diagnose
from p261_all_method_census import method_observation
from p295_raw_unknowns import instruction_bytes
from p296_instruction_shape import encoded_shape

# 35c ordinary method call opcodes and their 3rc /range equivalents.
FIXED = frozenset(range(0x6e, 0x73))
RANGE = frozenset(range(0x74, 0x79))
# invoke-polymorphic and invoke-custom each use additional pool kinds,
# which are intentionally NEVER claimed covered by this auditor.
EXTENDED = frozenset((0xfa, 0xfb, 0xfc, 0xfd))
METHOD_OPS = FIXED | RANGE
CATEGORIES = (
    "MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE",
    "DIFFERENT_INVOKE_METHOD_TARGET",
    "INVOKE_METHOD_POOL_UNAVAILABLE",
    "UNSUPPORTED_INVOKE_ENCODING",
    "NO_ORDINARY_INVOKE_OBSERVED",
    "INSTRUCTION_LAYOUT_UNVERIFIED",
)
LIMIT = 1000000

def raw_invokes(method):
    """Return all directly encoded standard invoke indices, or unknown."""
    raw = instruction_bytes(method)
    if raw is None:
        return None
    try:
        rows = list(method.get_instructions_idx())
        if not rows or len(rows) > LIMIT:
            return None
        calls = []
        for _, ins in rows:
            data = ins.get_raw()
            if not isinstance(data, bytes) or len(data) < 2:
                return None
            op = data[0]
            if op in EXTENDED:
                return "UNSUPPORTED"
            if op in METHOD_OPS:
                if len(data) != 6:
                    return None
                # DEX 35c and 3rc: BBBB references method_id_item.
                idx = data[2] | (data[3] << 8)
                calls.append((op, idx))
        return tuple(calls)
    except Exception:
        return None

def resolved(dex, idx):
    # Never reinterpret a display string as an index.
    return method_pool(dex, idx)

def category(a, b, da, db):
    sa = encoded_shape(a, b)
    if sa not in ("RAW_EXACT", "RAW_DIFFER_SAME_SHAPE"):
        return "INSTRUCTION_LAYOUT_UNVERIFIED"
    left, right = raw_invokes(a), raw_invokes(b)
    if left == "UNSUPPORTED" or right == "UNSUPPORTED":
        return "UNSUPPORTED_INVOKE_ENCODING"
    if left is None or right is None or not isinstance(left, tuple) or not isinstance(right, tuple):
        return "INVOKE_METHOD_POOL_UNAVAILABLE"
    if len(left) != len(right):
        return "INSTRUCTION_LAYOUT_UNVERIFIED"
    if not left:
        return "NO_ORDINARY_INVOKE_OBSERVED"
    compare = []
    for (oa,ia),(ob,ib) in zip(left,right):
        if oa != ob:
            return "INSTRUCTION_LAYOUT_UNVERIFIED"
        ta,tb = resolved(da,ia),resolved(db,ib)
        if ta is None or tb is None:
            return "INVOKE_METHOD_POOL_UNAVAILABLE"
        compare.append(ta == tb)
    return ("MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE" if all(compare)
            else "DIFFERENT_INVOKE_METHOD_TARGET")

def audit(original, candidate, da, db):
    previous = diagnose(original,candidate,da,db)
    total = previous["unknown"]
    out = Counter({name:0 for name in CATEGORIES})
    for key in sorted(original):
        a,b=original[key],candidate[key]
        if a.get_code() is None:
            continue
        if method_observation(a,b,da,db)["OPERANDS_NOT_ATTESTED"]:
            label=category(a,b,da,db)
            need(label in CATEGORIES,"P297_LABEL")
            out[label]+=1
    need(sum(out.values())==total,"P297_COUNT_RECONCILE")
    return {"count":total,"categories":dict(out)}

def emit(q):
    need(type(q) is dict and set(q)=={"count","categories"},"P297_REPORT")
    n,c=q["count"],q["categories"]
    need(type(n) is int and 0<=n<=LIMIT,"P297_COUNT")
    need(type(c) is dict and set(c)==set(CATEGORIES),"P297_FIELDS")
    need(all(type(v) is int and 0<=v<=n for v in c.values()) and sum(c.values())==n,
         "P297_SUM")
    print("P297_UNKNOWN_METHODS="+str(n))
    for name in CATEGORIES:
        print("P297_"+name+"="+str(c[name]))
    print("P297_STANDARD_INVOKE_METHOD_POOL_SCOPE_ONLY=YES")
    print("P297_OTHER_REFERENCE_KINDS=NOT_ATTESTED")
    print("P297_INVOKE_REGISTER_AND_ART_SEMANTICS=NOT_ATTESTED")
    print("P297_P245_ORIGINAL_GATE=UNCHANGED")
    print("P297_P192_ISOLATED_CHILD_EGRESS=NOT_ATTESTED")
    print("P297_RELEASE=DENY")
    print("P297_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    parser=argparse.ArgumentParser()
    for field in ("signed-original","base","candidate"):
        parser.add_argument("--"+field,type=Path)
    a=parser.parse_args()
    args=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in args):
        print("P297_SOURCE_ONLY=YES")
        print("P297_REAL_RAW_INVOKE_POOL=NOT_ATTESTED")
        print("P297_RELEASE=DENY")
        return 0
    try:
        need(all(x is not None for x in args),"P297_PINNED_THREE_APKS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        s=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",s):
            s="P297_DENY_UNEXPECTED"
        print(s,file=sys.stderr)
        return 2

if __name__=="__main__":raise SystemExit(main())
