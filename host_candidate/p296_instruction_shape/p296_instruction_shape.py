#!/usr/bin/env python3
"""P296: independent, fail-closed instruction-shape and reference-view census.

Uses the sealed-original P295/P263 unknown set. Raw instruction shape and the
Androguard operand *display view* are diagnostic; neither proves ART semantics,
pool-target identity, switch payload behavior or production P245 parity.
No private method identity, PC, raw bytes, reference content or hashes printed.
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
    "host_candidate/p295_raw_unknowns",
]
from p246_exception_semantics import decode, index, load, need
from p249_dual_diff import seal
from p261_all_method_census import method_observation
from p263_operand_correlation import diagnose
from p295_raw_unknowns import raw_comparison, reason

GROUPS = ("PAYLOAD", "INSTRUCTION_COUNT", "OPERAND_FORMAT", "OTHER")
SHAPES = (
    "RAW_EXACT",
    "RAW_DIFFER_COUNT",
    "RAW_DIFFER_WIDTH",
    "RAW_DIFFER_OPCODE",
    "RAW_DIFFER_SAME_SHAPE",
    "RAW_UNREADABLE",
)
REFS = (
    "DISPLAY_MATCH_ONLY",
    "DISPLAY_DIFFER",
    "NO_VISIBLE_INDEX_REFERENCES",
    "UNVERIFIED",
)
FIELDS = tuple(g + "_" + s for g in GROUPS for s in SHAPES)
REFERENCE_FIELDS = tuple(r for r in REFS)
LIMIT = 1000000

def encoded_shape(a, b):
    status = raw_comparison(a, b)
    if status == "UNREADABLE":
        return "RAW_UNREADABLE"
    if status == "EXACT_BYTES_ONLY":
        return "RAW_EXACT"
    try:
        old = list(a.get_instructions_idx())
        new = list(b.get_instructions_idx())
        if not old or not new or len(old) > LIMIT or len(new) > LIMIT:
            return "RAW_UNREADABLE"
        if len(old) != len(new):
            return "RAW_DIFFER_COUNT"
        for (_, x), (_, y) in zip(old, new):
            if x.get_length() != y.get_length():
                return "RAW_DIFFER_WIDTH"
        for (_, x), (_, y) in zip(old, new):
            if x.get_name() != y.get_name():
                return "RAW_DIFFER_OPCODE"
        return "RAW_DIFFER_SAME_SHAPE"
    except Exception:
        return "RAW_UNREADABLE"

def reference_display(method):
    """Enumerate ONLY visible get_operands() pool labels, not canonical IDs.

    A missing or malformed operand view remains UNVERIFIED. A method with no
    visible references is not claimed to have no actual indexed references.
    """
    try:
        items = list(method.get_instructions_idx())
        if not items or len(items) > LIMIT:
            return None
        out = []
        for ordinal, (_, ins) in enumerate(items):
            getter = getattr(ins, "get_operands", None)
            if not callable(getter):
                return None
            operands = getter()
            if not isinstance(operands, (list, tuple)) or len(operands) > 256:
                return None
            for operand in operands:
                if not isinstance(operand, (list, tuple)) or len(operand) < 2:
                    return None
                tag, index = operand[:2]
                if type(tag) is not int or type(index) is not int:
                    return None
                if 256 <= tag < 512:
                    if (len(operand) != 3 or index < 0 or
                        not isinstance(operand[2], str) or
                        not 0 < len(operand[2]) <= 8192):
                        return None
                    out.append((ordinal, tag, operand[2]))
                elif tag not in (0, 1, 3) or len(operand) != 2:
                    return None
        return tuple(out)
    except Exception:
        return None

def reference_category(a, b):
    left, right = reference_display(a), reference_display(b)
    if left is None or right is None:
        return "UNVERIFIED"
    if not left and not right:
        return "NO_VISIBLE_INDEX_REFERENCES"
    if left == right:
        return "DISPLAY_MATCH_ONLY"
    return "DISPLAY_DIFFER"

def audit(original, candidate, da, db):
    prior = diagnose(original, candidate, da, db)
    counts = Counter({name: 0 for name in FIELDS})
    refs = Counter({name: 0 for name in REFERENCE_FIELDS})
    for key in sorted(original):
        a, b = original[key], candidate[key]
        if a.get_code() is None:
            continue
        if method_observation(a, b, da, db)["OPERANDS_NOT_ATTESTED"]:
            group = reason(a, b, da, db)
            sh = encoded_shape(a, b)
            need(group in GROUPS and sh in SHAPES, "P296_CATEGORY")
            counts[group + "_" + sh] += 1
            refs[reference_category(a, b)] += 1
    need(sum(counts.values()) == prior["unknown"], "P296_TOTAL")
    need(sum(refs.values()) == prior["unknown"], "P296_REF_TOTAL")
    for group, old_name in zip(GROUPS, (
        "UNKNOWN_PAYLOAD", "UNKNOWN_INSTRUCTION_COUNT",
        "UNKNOWN_OPERAND_FORMAT", "UNKNOWN_OTHER",
    )):
        need(sum(counts[group + "_" + shape] for shape in SHAPES)
             == prior["counts"][old_name], "P296_P263_GROUP")
    return {"count": prior["unknown"], "shapes": dict(counts), "refs": dict(refs)}

def emit(q):
    need(type(q) is dict and set(q) == {"count", "shapes", "refs"}, "P296_SCHEMA")
    n, shapes, refs = q["count"], q["shapes"], q["refs"]
    need(type(n) is int and 0 <= n <= LIMIT, "P296_COUNT")
    need(type(shapes) is dict and set(shapes) == set(FIELDS), "P296_SHAPE_SCHEMA")
    need(type(refs) is dict and set(refs) == set(REFERENCE_FIELDS), "P296_REF_SCHEMA")
    need(all(type(v) is int and 0 <= v <= n for v in
             list(shapes.values()) + list(refs.values())), "P296_BOUNDS")
    need(sum(shapes.values()) == n and sum(refs.values()) == n, "P296_SUM")
    print("P296_UNKNOWN_METHODS=" + str(n))
    for name in FIELDS:
        print("P296_" + name + "=" + str(shapes[name]))
    for name in REFERENCE_FIELDS:
        print("P296_REF_" + name + "=" + str(refs[name]))
    for label, value in (
        ("RAW_BYTE_DIFFERENCES_ARE_NOT_BEHAVIORAL_FAILURE", "YES"),
        ("RAW_EXACT_METHODS_POOL_TARGET_IDENTITY", "NOT_ATTESTED"),
        ("VISIBLE_REFERENCE_TEXT_IS_NOT_CANONICAL_PROOF", "YES"),
        ("SWITCH_PAYLOAD_CONTROL_FLOW", "NOT_ATTESTED"),
        ("P245_ORIGINAL_GATE", "UNMODIFIED"),
        ("ART_P192_ISOLATION", "NOT_ATTESTED"),
        ("RELEASE", "DENY"),
        ("V139", "STRUCTURAL_BLOCKED"),
    ):
        print("P296_" + label + "=" + value)
    return 2

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--signed-original", type=Path)
    p.add_argument("--base", type=Path)
    p.add_argument("--candidate", type=Path)
    a = p.parse_args()
    args = (a.signed_original, a.base, a.candidate)
    if all(x is None for x in args):
        print("P296_SOURCE_ONLY=YES")
        print("P296_REAL_REFERENCE_AND_SHAPE=NOT_ATTESTED")
        print("P296_NO_APK_SIGN_ADB_INSTALL_OR_RELEASE=YES")
        return 0
    try:
        need(all(x is not None for x in args), "P296_INPUT_TRIO")
        seal(a.signed_original)
        da, db = load(a.base), load(a.candidate)
        return emit(audit(index(da), index(db), da, db))
    except Exception as e:
        code = str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}", code):
            code = "P296_DENY_UNEXPECTED"
        print(code, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
