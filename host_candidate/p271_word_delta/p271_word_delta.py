#!/usr/bin/env python3
"""P271 - private raw DEX 35c/3rc argument WORD delta classification (DENY only).

Independent second-stage audit of P270 NONZERO_REGISTER_WORDS_DIFFER. The raw
instruction words are decoded by immutable P267; comparison additionally checks
the independently resolved method pool, frames, and wide-argument layout.
No method names, offsets, registers, index values or descriptors are emitted.
No release / P245 / P47 / P192 / B3 permissions are conferred.
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
]
from p246_exception_semantics import decode, index, load, need
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p261_all_method_census import method_observation, opaque
from p259_all_operands import pair
from p263_operand_correlation import changed_kind
from p265_operand_shape import shape_cause
from p267_invoke_words import FIXED, RANGE, classify as p267_classify
from p267_invoke_words import raw_words, type_widths, wide_valid
from p269_method_pool import audit as p269_audit, classify_pool, method_pool, signature

WORD_CATEGORIES = (
    "COUNT_CHANGED",
    "SAME_COUNT_FIXED_NONCONTIGUOUS",
    "SAME_COUNT_CONTIGUOUS_DIFFERENT",
    "SAME_COUNT_WORD_SEQUENCE_MATCH",
    "RAW_UNREADABLE",
    "ENCODING_UNSUPPORTED",
)
REF_CATEGORIES = ("POOL_MATCH", "POOL_DIFFER", "POOL_UNREADABLE")
PROTO_CATEGORIES = ("VALID_BOTH", "INVALID_OR_UNKNOWN", "NOT_APPLICABLE")
FRAME_CATEGORIES = ("VALID_BOTH", "DIFFERENT", "INVALID_OR_UNKNOWN")
WIDE_CATEGORIES = ("VALID_BOTH", "INVALID_ANY", "NOT_ATTESTED")
# All observations remain LOCAL DIAGNOSTICS, not ART semantics or P245 parity.

def contiguous(words):
    """Strictly compare encoded word positions, never infer register semantics."""
    return all(words[i] == words[i-1] + 1 for i in range(1, len(words)))

def pair_detail(x, y, a, b, dex_a, dex_b):
    """Only fixed-label category tuple leaves this function; no raw data logged."""
    names = (x[1], y[1])
    if not ((names[0] in FIXED and names[1] in RANGE) or
            (names[0] in RANGE and names[1] in FIXED)):
        return ("ENCODING_UNSUPPORTED", "POOL_UNREADABLE",
                "NOT_APPLICABLE", "INVALID_OR_UNKNOWN", "NOT_ATTESTED")
    if names[0].removesuffix("/range") != names[1].removesuffix("/range"):
        return ("ENCODING_UNSUPPORTED", "POOL_UNREADABLE",
                "NOT_APPLICABLE", "INVALID_OR_UNKNOWN", "NOT_ATTESTED")
    decoded_a, decoded_b = raw_words(x), raw_words(y)
    if decoded_a is None or decoded_b is None:
        return ("RAW_UNREADABLE", "POOL_UNREADABLE",
                "NOT_APPLICABLE", "INVALID_OR_UNKNOWN", "NOT_ATTESTED")

    words_a, index_a = decoded_a
    words_b, index_b = decoded_b
    fixed_words = words_a if names[0] in FIXED else words_b
    if len(words_a) != len(words_b):
        word = "COUNT_CHANGED"
    elif words_a == words_b:
        word = "SAME_COUNT_WORD_SEQUENCE_MATCH"
    elif not contiguous(fixed_words):
        word = "SAME_COUNT_FIXED_NONCONTIGUOUS"
    else:
        word = "SAME_COUNT_CONTIGUOUS_DIFFERENT"

    try:
        f_a, f_b = a.get_code(), b.get_code()
        frames = tuple((
            getattr(frame, method)()
            for method in ("get_registers_size", "get_ins_size", "get_outs_size")
        ) for frame in (f_a, f_b))
    except Exception:
        frames = ()
    if (len(frames) != 2 or any(
            type(n) is not int or not (0 <= n <= 65535)
            for tup in frames for n in tup)):
        frame_cat = "INVALID_OR_UNKNOWN"
    elif frames[0] != frames[1]:
        frame_cat = "DIFFERENT"
    elif (len(words_a) > frames[0][2] or len(words_b) > frames[1][2] or
          any(reg >= frames[0][0] for reg in words_a) or
          any(reg >= frames[1][0] for reg in words_b)):
        frame_cat = "INVALID_OR_UNKNOWN"
    else:
        frame_cat = "VALID_BOTH"

    pool_a = method_pool(dex_a, index_a)
    pool_b = method_pool(dex_b, index_b)
    if pool_a is None or pool_b is None:
        ref_cat = "POOL_UNREADABLE"
    elif pool_a != pool_b:
        ref_cat = "POOL_DIFFER"
    else:
        ref_cat = "POOL_MATCH"

    proto_cat = "NOT_APPLICABLE"
    wide_cat = "NOT_ATTESTED"
    # Check the true method prototype even if the encoded words disagree.
    # Do NOT assume wide-layout is valid merely because word counts agree.
    if ref_cat == "POOL_MATCH":
        is_static = names[0].startswith("invoke-static")
        widths = type_widths(signature(pool_a), is_static)
        if widths is None:
            proto_cat = "INVALID_OR_UNKNOWN"
        else:
            proto_cat = "VALID_BOTH"
            wide_cat = (
                "VALID_BOTH"
                if wide_valid(words_a, widths) and wide_valid(words_b, widths)
                else "INVALID_ANY"
            )
    return (word, ref_cat, proto_cat, frame_cat, wide_cat)

def audit(original, derived, da, db):
    prior = p269_audit(original, derived, da, db)
    expected = prior["counts"]["NONZERO_REGISTER_WORDS_DIFFER"]
    totals = [
        Counter({x: 0 for x in cats})
        for cats in (WORD_CATEGORIES, REF_CATEGORIES, PROTO_CATEGORIES,
                     FRAME_CATEGORIES, WIDE_CATEGORIES)
    ]
    observed = 0
    for key in sorted(original):
        a, b = original[key], derived[key]
        if a.get_code() is None:
            continue
        la, lb = decode(a, da), decode(b, db)
        if not method_observation(a, b, da, db, la, lb)["OPERANDS_STRUCTURED_DIFFER"]:
            continue
        if opaque(a) or opaque(b):
            continue
        rows_a, rows_b = instructions(a, la), instructions(b, lb)
        if len(rows_a) != len(rows_b):
            continue
        differences = [(x,y) for x,y in zip(rows_a, rows_b)
                       if pair(x,y) == "STRUCTURED_DIFFER"]
        hits = [(x,y) for x,y in differences
                if changed_kind(x,y) == "OPERAND_SHAPE"
                and shape_cause(x,y) == "NORMALIZED_ITEM_COUNT"]
        if len(hits) != 1 or len(differences) != 1:
            continue
        x, y = hits[0]
        if p267_classify(x, y, a, b) != "INVOKE_REFERENCE_NOT_ATTESTED":
            continue
        if classify_pool(x, y, a, b, da, db) != "NONZERO_REGISTER_WORDS_DIFFER":
            continue
        result = pair_detail(x, y, a, b, da, db)
        for counts, cats, category in zip(
                totals, (WORD_CATEGORIES, REF_CATEGORIES, PROTO_CATEGORIES,
                         FRAME_CATEGORIES, WIDE_CATEGORIES), result):
            need(category in cats, "CATEGORY_ENUM")
            counts[category] += 1
        observed += 1
    need(observed == expected, "P270_P271_COUNT_RECONCILIATION")
    return {
        "counts": [dict(c) for c in totals],
        "examined": expected,
        "prior_unknown_methods": prior["prior_unknown"],
        "prior_ref_unverified": prior["ref_unknown"],
    }

def emit(result):
    need(type(result) is dict and
         set(result) == {"counts", "examined", "prior_unknown_methods",
                         "prior_ref_unverified"}, "SCHEMA")
    categories = (WORD_CATEGORIES, REF_CATEGORIES, PROTO_CATEGORIES,
                  FRAME_CATEGORIES, WIDE_CATEGORIES)
    counts = result["counts"]
    n = result["examined"]
    need(type(n) is int and 0 <= n <= 1000000, "N")
    need(type(result["prior_unknown_methods"]) is int and
         0 <= result["prior_unknown_methods"] <= 1000000 and
         type(result["prior_ref_unverified"]) is int and
         n <= result["prior_ref_unverified"] <= 1000000, "PREVIOUS")
    need(type(counts) is list and len(counts) == len(categories), "COUNT_GROUPS")
    for c, names in zip(counts, categories):
        need(type(c) is dict and set(c) == set(names), "COUNT_KEYS")
        need(all(type(v) is int and 0 <= v <= n for v in c.values())
             and sum(c.values()) == n, "COUNT_RECONCILIATION")
    for prefix, group in zip(("WORDS", "METHOD_REF", "PROTOTYPE", "FRAME", "WIDE"),
                             counts):
        for k, value in group.items():
            print("P271_" + prefix + "_" + k + "=" + str(value))
    print("P271_P270_NONZERO_WORD_MISMATCHES=" + str(n))
    print("P271_P270_REFERENCE_NOT_ATTESTED=" + str(result["prior_ref_unverified"]))
    print("P271_UNVERIFIED_ORIGINAL_METHODS=" + str(result["prior_unknown_methods"]))
    print("P271_PRIVATE_METHODS_PCS_REGISTERS_AND_REFERENCES=WITHHELD")
    print("P271_LOCAL_ENCODING_CANDIDATE_ONLY=YES")
    print("P271_ART_SEMANTICS_AND_P245_FULL_PARITY=NOT_ATTESTED")
    print("P271_RELEASE=DENY")
    print("P271_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p = argparse.ArgumentParser()
    for arg in ("signed-original", "base", "candidate"):
        p.add_argument("--" + arg, type=Path)
    args = p.parse_args()
    paths = (args.signed_original, args.base, args.candidate)
    if all(x is None for x in paths):
        print("P271_SOURCE_ONLY=YES")
        print("P271_REAL_WORD_DIFFERENCE=NOT_ATTESTED")
        print("P271_RELEASE=DENY")
        print("P271_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths), "THREE_PINNED_INPUTS")
        seal(args.signed_original)
        da, db = load(args.base), load(args.candidate)
        return emit(audit(index(da), index(db), da, db))
    except Exception as e:
        code = str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}", code):
            code = "P271_DENY_UNEXPECTED"
        print(code, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
