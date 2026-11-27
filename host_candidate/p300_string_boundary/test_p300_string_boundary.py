#!/usr/bin/env python3
"""P300 negative fixtures for one dual-side P299 string-validation anomaly."""
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

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
from p246_exception_semantics import Deny
from test_p298_other_pool_refs import Pool, same, method, op
from test_p295_raw_unknowns import Ins
import p300_string_boundary as p300

def two(a, b):
    return p300.classify(same(0x1a), same(0x1a),
                         Pool(strings={1:a}), Pool(strings={1:b}))
def prior():
    return {"unavailable":1,"causes":{"STRING_VALUE_INVALID":1},
            "sides":{"BOTH":1}}

class Tests(unittest.TestCase):
    def test_01_both_long_exact_decoded(self):
        self.assertEqual(two("A"*8193,"A"*8193),
                         "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_02_both_long_different(self):
        self.assertEqual(two("A"*8193,"B"*8193),
                         "BOTH_OVER_8192_DIFFERENT_DECODED_TEXT")
    def test_03_both_long_length_diff(self):
        self.assertEqual(two("A"*8193,"A"*8194),
                         "BOTH_OVER_8192_LENGTH_DIFFER")
    def test_04_exact_boundary_is_not_invalid(self):
        self.assertEqual(two("A"*8192,"A"*8192),
                         "NO_INVALID_STRING_REPRODUCED")
    def test_05_one_above_boundary(self):
        self.assertEqual(two("A"*8193,"A"*8192),
                         "MIXED_INVALID_TYPES_OR_LENGTH")
    def test_06_both_nonstring(self):
        self.assertEqual(two(None,None),"BOTH_NONSTRING")
    def test_07_one_nonstring(self):
        self.assertEqual(two(None,"A"*8193),
                         "MIXED_INVALID_TYPES_OR_LENGTH")
    def test_08_both_bytes_never_coerced(self):
        self.assertEqual(two(b"A"*8193,b"A"*8193),"BOTH_NONSTRING")
    def test_09_type_string_mix(self):
        self.assertEqual(two(123, "A"*8193),"MIXED_INVALID_TYPES_OR_LENGTH")
    def test_10_both_above_limit_refuse_full_compare(self):
        s="A"*(p300.MAX_CHARS+1)
        self.assertEqual(two(s,s),"BOTH_OVER_COMPARISON_BOUND")
    def test_11_one_above_limit_refuse_full_compare(self):
        s="A"*(p300.MAX_CHARS+1)
        self.assertEqual(two(s,"A"*8193),"BOTH_OVER_COMPARISON_BOUND")
    def test_12_get_string_raises_on_base(self):
        self.assertEqual(p300.classify(same(0x1a),same(0x1a),
                         Pool(strings={}),Pool(strings={1:"A"*8193})),
                         "LOOKUP_FAILED")
    def test_13_get_string_raises_on_candidate(self):
        self.assertEqual(p300.classify(same(0x1a),same(0x1a),
                         Pool(strings={1:"A"*8193}),Pool(strings={})),
                         "LOOKUP_FAILED")
    def test_14_two_invalid_string_indices(self):
        a=method(op(0x1a,1),op(0x1a,2))
        d=Pool(strings={1:"A"*8193,2:"B"*8193})
        self.assertEqual(p300.classify(a,a,d,d),
                         "MULTIPLE_INVALID_REFERENCES")
    def test_15_one_invalid_one_valid(self):
        a=method(op(0x1a,1),op(0x1a,2))
        d=Pool(strings={1:"A"*8193,2:"ok"})
        self.assertEqual(p300.classify(a,a,d,d),
                         "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_16_no_string_refs(self):
        self.assertEqual(p300.classify(method(),method(),Pool(),Pool()),
                         "NO_INVALID_STRING_REPRODUCED")
    def test_17_type_reference_not_treated_as_string(self):
        a=same(0x1c)
        self.assertEqual(p300.classify(a,a,Pool(),Pool()),
                         "NO_INVALID_STRING_REPRODUCED")
    def test_18_wrong_raw_size_fails_closed(self):
        a=method(Ins("bad",b"\x1a\x00\x01\x00\x00\x00"))
        self.assertEqual(p300.classify(a,a,Pool(),Pool()),
                         "REFERENCE_POSITION_UNVERIFIED")
    def test_19_different_opcode_layout(self):
        self.assertEqual(p300.classify(same(0x1a),same(0x1c),Pool(),Pool()),
                         "RAW_LAYOUT_UNVERIFIED")
    def test_20_gapped_pc_rejected(self):
        a=same(0x1a);a.rows[0]=(2,a.rows[0][1])
        self.assertEqual(p300.classify(a,same(0x1a),Pool(),Pool()),
                         "RAW_LAYOUT_UNVERIFIED")
    def test_21_jumbo_string_both_long(self):
        a=same(0x1b,65537);d=Pool(strings={65537:"Z"*8193})
        self.assertEqual(p300.classify(a,a,d,d),
                         "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_22_jumbo_string_diff_same_shape(self):
        a=same(0x1b,65537);b=same(0x1b,65538)
        da=Pool(strings={65537:"Z"*8193})
        db=Pool(strings={65538:"Z"*8193})
        self.assertEqual(p300.classify(a,b,da,db),
                         "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_23_embedded_nul_preserved(self):
        x="a\x00" + "B"*8192
        self.assertEqual(two(x,x),"BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_24_surrogate_not_silently_normalized(self):
        a="\ud800"+"A"*8192
        b="\ud801"+"A"*8192
        self.assertEqual(two(a,b),"BOTH_OVER_8192_DIFFERENT_DECODED_TEXT")
    def test_25_issue_does_not_claim_semantic_equivalence(self):
        self.assertEqual(p300.issue("A"*8193,"A"*8193),
                         "BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE")
    def test_26_audit_both_one_case(self):
        a=same(0x1a);da=Pool(strings={1:"A"*8193})
        with patch.object(p300,"p299_audit",return_value=prior()),\
             patch.object(p300,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p300,"p299_classify",return_value=("STRING_VALUE_INVALID","BOTH")):
            q=p300.audit({("x",):a},{("x",):a},da,da)
        self.assertEqual(q["categories"]["BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE"],1)
    def test_27_audit_broken_previous_count(self):
        a=same(0x1a);old=prior();old["sides"]["BOTH"]=0
        with patch.object(p300,"p299_audit",return_value=old):
            with self.assertRaises(Deny):p300.audit({("x",):a},{("x",):a},Pool(),Pool())
    def test_28_audit_missing_reproduced_case(self):
        a=same(0x1a)
        with patch.object(p300,"p299_audit",return_value=prior()),\
             patch.object(p300,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p300,"p299_classify",return_value=None):
            with self.assertRaises(Deny):p300.audit({("x",):a},{("x",):a},Pool(),Pool())
    def test_29_emit_always_deny(self):
        c={k:0 for k in p300.CATEGORIES}
        c["BOTH_OVER_8192_SAME_DECODED_TEXT_CANDIDATE"]=1
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(p300.emit({"count":1,"categories":c}),2)
        s=output.getvalue()
        self.assertIn("P300_RELEASE=DENY",s)
        self.assertIn("P300_ORIGINAL_MUTF8_BYTES=NOT_ATTESTED",s)
        self.assertNotIn("B"*8193,s)
    def test_30_emit_forged_total_denied(self):
        c={k:0 for k in p300.CATEGORIES}
        with self.assertRaises(Deny):p300.emit({"count":1,"categories":c})
    def test_31_emit_extra_fields_denied(self):
        c={k:0 for k in p300.CATEGORIES};c["ALLOW"]=1
        with self.assertRaises(Deny):p300.emit({"count":1,"categories":c})
    def test_32_source_no_real_proof(self):
        old=sys.argv;sys.argv=["p300"]
        try:
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(p300.main(),0)
            self.assertIn("P300_REAL_INVALID_STRING_CLASS=NOT_ATTESTED",output.getvalue())
            self.assertIn("P300_RELEASE=DENY",output.getvalue())
        finally:sys.argv=old

if __name__=="__main__":unittest.main()
