#!/usr/bin/env python3
"""P300: read-only, narrow, fail-closed P299 dual invalid-string diagnosis.

Original P298 caps decoded string length at 8192. That is an auditor bound,
not a DEX rule. This analyzer does not alter P298/P299 or pronounce equality
of byte-encoded MUTF-8 and runtime semantics. It compares only bounded
Python decoded strings privately. Never print raw strings, names, offsets,
indices, hashes, account data, or source methods. Release always DENY.
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
    "host_candidate/p297_raw_invoke_pool",
    "host_candidate/p298_other_pool_refs",
    "host_candidate/p299_pool_gap",
]
from p246_exception_semantics import need, index, load
from p249_dual_diff import seal
from p263_operand_correlation import diagnose
from p261_all_method_census import method_observation
from p295_raw_unknowns import instruction_bytes
from p296_instruction_shape import encoded_shape
from p299_pool_gap import audit as p299_audit, classify as p299_classify

MAX_CHARS = 1000000
VALIDATOR_LIMIT = 8192
CATEGORIES = (
    "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE",
    "BOTH_OVER_8192_DIFFERENT_DECODED_TEXT",
    "BOTH_OVER_8192_LENGTH_DIFFER",
    "BOTH_OVER_COMPARISON_BOUND",
    "BOTH_NONSTRING",
    "MIXED_INVALID_TYPES_OR_LENGTH",
    "LOOKUP_FAILED",
    "REFERENCE_POSITION_UNVERIFIED",
    "RAW_LAYOUT_UNVERIFIED",
    "MULTIPLE_INVALID_REFERENCES",
    "NO_INVALID_STRING_REPRODUCED",
)
STATUS = ("BOTH", "NOT_ATTESTED")
SENTINEL = object()

def snapshot(method, dex):
    """Private raw 21c/31c string references, indexed by instruction ordinal."""
    if instruction_bytes(method) is None:
        return None
    try:
        out = []
        for pos, (_, ins) in enumerate(method.get_instructions_idx()):
            raw = ins.get_raw()
            if type(raw) is not bytes or len(raw) < 2:
                return None
            op = raw[0]
            if op not in (0x1a, 0x1b):
                continue
            width = 2 if op == 0x1a else 4
            if len(raw) != 2 + width:
                return None
            idx = int.from_bytes(raw[2:2+width], "little")
            try:
                value = dex.get_cm_string(idx)
            except Exception:
                value = SENTINEL
            out.append((pos, op, value))
        return tuple(out)
    except Exception:
        return None

def raw_opcodes(method):
    """Require matching *encoded* opcodes, even if parser instruction labels lie."""
    if instruction_bytes(method) is None:
        return None
    try:
        result = []
        for _, ins in method.get_instructions_idx():
            data = ins.get_raw()
            if type(data) is not bytes or not data:
                return None
            result.append(data[0])
        return tuple(result)
    except Exception:
        return None

def invalid(v):
    return not isinstance(v, str) or len(v) > VALIDATOR_LIMIT

def issue(a, b):
    if a is SENTINEL or b is SENTINEL:
        return "LOOKUP_FAILED"
    if not isinstance(a, str) and not isinstance(b, str):
        return "BOTH_NONSTRING"
    if not isinstance(a, str) or not isinstance(b, str):
        return "MIXED_INVALID_TYPES_OR_LENGTH"
    if len(a) <= VALIDATOR_LIMIT or len(b) <= VALIDATOR_LIMIT:
        return "MIXED_INVALID_TYPES_OR_LENGTH"
    if len(a) > MAX_CHARS or len(b) > MAX_CHARS:
        return "BOTH_OVER_COMPARISON_BOUND"
    if len(a) != len(b):
        return "BOTH_OVER_8192_LENGTH_DIFFER"
    if a == b:
        return "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE"
    return "BOTH_OVER_8192_DIFFERENT_DECODED_TEXT"

def classify(method_a, method_b, dex_a, dex_b):
    shape = encoded_shape(method_a, method_b)
    if shape not in ("RAW_EXACT", "RAW_DIFFER_SAME_SHAPE"):
        return "RAW_LAYOUT_UNVERIFIED"
    # Synthetic parser labels and pretty-printer output are untrusted.
    # Compare opcode *bytes* before correlating individual raw string indices.
    op_a, op_b = raw_opcodes(method_a), raw_opcodes(method_b)
    if op_a is None or op_b is None or op_a != op_b:
        return "RAW_LAYOUT_UNVERIFIED"
    aa, bb = snapshot(method_a, dex_a), snapshot(method_b, dex_b)
    if aa is None or bb is None or len(aa) != len(bb):
        return "REFERENCE_POSITION_UNVERIFIED"
    problem = []
    for left, right in zip(aa, bb):
        if left[:2] != right[:2]:
            return "REFERENCE_POSITION_UNVERIFIED"
        va, vb = left[2], right[2]
        if invalid(va) or invalid(vb):
            problem.append(issue(va, vb))
    if not problem:
        return "NO_INVALID_STRING_REPRODUCED"
    if len(problem) != 1:
        return "MULTIPLE_INVALID_REFERENCES"
    return problem[0]

def audit(original, derived, base, candidate):
    prior = p299_audit(original, derived, base, candidate)
    need(prior["unavailable"] == 1 and
         prior["causes"]["STRING_VALUE_INVALID"] == 1 and
         prior["sides"]["BOTH"] == 1, "P300_P299_EXACT_BOUNDARY")
    out = Counter({x: 0 for x in CATEGORIES})
    seen = 0
    for key in sorted(original):
        a, b = original[key], derived[key]
        if a.get_code() is None:
            continue
        if not method_observation(a, b, base, candidate)["OPERANDS_NOT_ATTESTED"]:
            continue
        if p299_classify(a, b, base, candidate) == ("STRING_VALUE_INVALID", "BOTH"):
            outcome = classify(a, b, base, candidate)
            need(outcome in CATEGORIES, "P300_CATEGORY")
            out[outcome] += 1
            seen += 1
    need(seen == 1 and sum(out.values()) == seen, "P300_SINGLE_REPRODUCED")
    return {"count": seen, "categories": dict(out)}

def emit(q):
    need(type(q) is dict and set(q) == {"count", "categories"}, "P300_RESULT")
    n, c = q["count"], q["categories"]
    need(type(n) is int and n in (0, 1) and
         type(c) is dict and set(c) == set(CATEGORIES), "P300_SCHEMA")
    need(all(type(v) is int and 0 <= v <= n for v in c.values())
         and sum(c.values()) == n, "P300_COUNT")
    print("P300_P299_BOTH_INVALID_CASES=" + str(n))
    for name in CATEGORIES:
        print("P300_" + name + "=" + str(c[name]))
    print("P300_DECODED_TEXT_MATCH_IS_ONLY_CANDIDATE=YES")
    print("P300_ORIGINAL_MUTF8_BYTES=NOT_ATTESTED")
    print("P300_OTHER_DEX_REFERENCES_AND_PAYLOADS=NOT_ATTESTED")
    print("P300_ORIGINAL_P245=UNCHANGED")
    print("P300_ART_P192_B3_B4=NOT_ATTESTED")
    print("P300_RELEASE=DENY")
    print("P300_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p = argparse.ArgumentParser()
    for name in ("signed-original", "base", "candidate"):
        p.add_argument("--" + name, type=Path)
    x = p.parse_args()
    paths = (x.signed_original, x.base, x.candidate)
    if all(v is None for v in paths):
        print("P300_SOURCE_ONLY=YES")
        print("P300_REAL_INVALID_STRING_CLASS=NOT_ATTESTED")
        print("P300_RELEASE=DENY")
        return 0
    try:
        need(all(v is not None for v in paths), "P300_THREE_PINNED_FILES")
        seal(x.signed_original)
        base, candidate = load(x.base), load(x.candidate)
        return emit(audit(index(base), index(candidate), base, candidate))
    except Exception as exc:
        msg = str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}", msg):
            msg = "P300_DENY_UNEXPECTED"
        print(msg, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
