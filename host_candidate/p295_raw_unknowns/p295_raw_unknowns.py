#!/usr/bin/env python3
"""P295: independently triage P263 UNKNOWN methods by *raw instruction bytes*.

Byte equality is encoding evidence ONLY. Indexed DEX reference targets, payload
semantics, Android ART execution, process ownership and original P245 remain
NOT_ATTESTED. No method names, raw bytes, indices, addresses or hashes printed.
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
]
from p246_exception_semantics import Deny, decode, index, load, need
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p259_all_operands import pair
from p261_all_method_census import method_observation, opaque
from p263_operand_correlation import diagnose

REASONS = ("PAYLOAD", "INSTRUCTION_COUNT", "OPERAND_FORMAT", "OTHER")
RAW = ("EXACT_BYTES_ONLY", "DIFFERENT_BYTES", "UNREADABLE")
FIELDS = tuple("UNKNOWN_" + reason + "_" + raw for reason in REASONS for raw in RAW)
LIMIT = 1000000

def instruction_bytes(method):
    """Extract original encoded bytes, refusing synthesized or lossy objects."""
    try:
        code = method.get_code()
        total = code.get_insns_size()
        if type(total) is not int or not 0 < total <= LIMIT:
            return None
        rows = list(method.get_instructions_idx())
        if not 0 < len(rows) <= LIMIT:
            return None
        offset = 0
        parts = []
        for pc, ins in rows:
            if type(pc) is not int or pc != offset or pc % 2:
                return None
            width = ins.get_length()
            if type(width) is not int or width < 2 or width > 65536 or width % 2:
                return None
            raw_getter = getattr(ins, "get_raw", None)
            if not callable(raw_getter):
                return None
            data = raw_getter()
            if type(data) is not bytes or len(data) != width:
                return None
            parts.append(data)
            offset += width
            if offset > 2 * total:
                return None
        if offset != 2 * total:
            return None
        data = b"".join(parts)
        return data if len(data) == 2 * total else None
    except Exception:
        return None

def raw_comparison(a, b):
    left, right = instruction_bytes(a), instruction_bytes(b)
    if left is None or right is None:
        return "UNREADABLE"
    return "EXACT_BYTES_ONLY" if left == right else "DIFFERENT_BYTES"

def reason(a, b, da, db):
    """Mirror P263 unknown buckets, not unverified -> 'safe' inference."""
    if opaque(a) or opaque(b):
        return "PAYLOAD"
    try:
        la, lb = decode(a, da), decode(b, db)
        ra, rb = instructions(a, la), instructions(b, lb)
        if len(ra) != len(rb):
            return "INSTRUCTION_COUNT"
        if any(pair(x, y) == "NOT_ATTESTED" for x, y in zip(ra, rb)):
            return "OPERAND_FORMAT"
    except Deny:
        return "OTHER"
    return "OTHER"

def classify(a, b, da, db):
    return "UNKNOWN_" + reason(a, b, da, db) + "_" + raw_comparison(a, b)

def audit(original, derived, da, db):
    """Reconcile counts against P263, preserving immutable release denial."""
    previous = diagnose(original, derived, da, db)
    n = previous["unknown"]
    need(type(n) is int and 0 <= n <= LIMIT, "P295_UNKNOWN_COUNT")
    totals = Counter({key: 0 for key in FIELDS})
    for key in sorted(original):
        a, b = original[key], derived[key]
        if a.get_code() is None:
            continue
        obs = method_observation(a, b, da, db)
        if obs["OPERANDS_NOT_ATTESTED"]:
            category = classify(a, b, da, db)
            need(category in totals, "P295_UNKNOWN_CLASSIFICATION")
            totals[category] += 1
    need(sum(totals.values()) == n, "P295_TOTAL_COUNT")
    categories = previous["counts"]
    for reason_name, old_key in (
        ("PAYLOAD", "UNKNOWN_PAYLOAD"),
        ("INSTRUCTION_COUNT", "UNKNOWN_INSTRUCTION_COUNT"),
        ("OPERAND_FORMAT", "UNKNOWN_OPERAND_FORMAT"),
        ("OTHER", "UNKNOWN_OTHER"),
    ):
        need(sum(totals["UNKNOWN_" + reason_name + "_" + flag] for flag in RAW)
             == categories[old_key], "P295_PRIOR_CATEGORY_RECONCILIATION")
    return dict(counts=dict(totals), total=n)

def emit(report):
    need(type(report) is dict and set(report) == {"counts", "total"}, "P295_REPORT")
    counts, n = report["counts"], report["total"]
    need(type(counts) is dict and set(counts) == set(FIELDS), "P295_SCHEMA")
    need(type(n) is int and 0 <= n <= LIMIT, "P295_TOTAL_BOUND")
    need(all(type(v) is int and 0 <= v <= n for v in counts.values()),
         "P295_COUNT_BOUND")
    need(sum(counts.values()) == n, "P295_COUNT_SUM")
    print("P295_UNVERIFIED_ORIGINAL_METHODS=" + str(n))
    for key in FIELDS:
        print("P295_" + key + "=" + str(counts[key]))
    print("P295_RAW_EXACT_NEVER_MEANS_SEMANTIC_EQUALITY=YES")
    print("P295_REFERENCE_POOL_TARGETS=NOT_ATTESTED")
    print("P295_SWITCH_PAYLOAD_SEMANTICS=NOT_ATTESTED")
    print("P295_P245_ORIGINAL_GATE=UNMODIFIED")
    print("P295_ART_AND_P192_PROCESS_ISOLATION=NOT_ATTESTED")
    print("P295_RELEASE=DENY")
    print("P295_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--signed-original", type=Path)
    p.add_argument("--base", type=Path)
    p.add_argument("--candidate", type=Path)
    a = p.parse_args()
    inp = (a.signed_original, a.base, a.candidate)
    if all(x is None for x in inp):
        print("P295_SOURCE_ONLY=YES")
        print("P295_REAL_RAW_METHOD_CENSUS=NOT_ATTESTED")
        print("P295_NO_APK_ADB_SIGN_INSTALL_OR_RELEASE=YES")
        print("P295_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in inp), "P295_ALL_PINNED_INPUTS")
        seal(a.signed_original)
        da, db = load(a.base), load(a.candidate)
        return emit(audit(index(da), index(db), da, db))
    except Exception as exc:
        code = str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}", code):
            code = "P295_DENY_UNEXPECTED"
        print(code, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
