#!/usr/bin/env python3
"""P297: adversarial source-only raw method pool index fixtures."""
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

sys.path[:0]=[
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
from test_p295_raw_unknowns import Ins,Method
from p246_exception_semantics import Deny
import p297_raw_invoke_pool as p297

class Pool:
    def __init__(self, table):self.table=table
    def get_cm_method(self, idx):return self.table[idx]
REF=("Lsample/Record;","call",("(I)","V"))
REF_OTHER=("Lsample/Record;","another",("(I)","V"))
def invoke(op=0x71,index=1,reg=b"\x00\x00"):
    return Ins("invoke-static" if op==0x71 else "invoke-virtual",
               bytes((op,0x10,index & 255,index >> 8))+reg, ())
def method(*ops):
    return Method(*(ops or (Ins("return-void",b"\x0e\x00",()),)))

class Cases(unittest.TestCase):
    def setUp(self):
        self.a=Pool({1:REF,2:REF,3:REF_OTHER})
        self.b=Pool({1:REF,2:REF,3:REF_OTHER})
    def test_01_method_id_35c(self):
        self.assertEqual(p297.raw_invokes(method(invoke())),((0x71,1),))
    def test_02_method_id_3rc(self):
        self.assertEqual(p297.raw_invokes(method(invoke(0x77,2))),((0x77,2),))
    def test_03_two_invokes(self):
        self.assertEqual(p297.raw_invokes(method(invoke(),invoke(0x77,2))),
                         ((0x71,1),(0x77,2)))
    def test_04_high_byte_index(self):
        self.assertEqual(p297.raw_invokes(method(invoke(index=258))),((0x71,258),))
    def test_05_zero_registers_still_ref(self):
        self.assertEqual(p297.raw_invokes(method(invoke(reg=b"\x00\x00"))),((0x71,1),))
    def test_06_raw_ref_match(self):
        a,b=method(invoke()),method(invoke(index=2))
        self.assertEqual(p297.category(a,b,self.a,self.b),
                         "MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE")
    def test_07_raw_ref_diff(self):
        self.assertEqual(p297.category(method(invoke()),method(invoke(index=3)),self.a,self.b),
                         "DIFFERENT_INVOKE_METHOD_TARGET")
    def test_08_same_bytes_pool_diff(self):
        other=Pool({1:REF_OTHER})
        self.assertEqual(p297.category(method(invoke()),method(invoke()),self.a,other),
                         "DIFFERENT_INVOKE_METHOD_TARGET")
    def test_09_empty_invoke_does_not_claim_all_refs(self):
        self.assertEqual(p297.category(method(),method(),self.a,self.b),
                         "NO_ORDINARY_INVOKE_OBSERVED")
    def test_10_unknown_method_ref(self):
        self.assertEqual(p297.category(method(invoke()),method(invoke(index=4)),self.a,self.b),
                         "INVOKE_METHOD_POOL_UNAVAILABLE")
    def test_11_unrecognized_format_polymorphic(self):
        x=method(invoke(op=0xfa))
        self.assertEqual(p297.category(x,x,self.a,self.b),
                         "UNSUPPORTED_INVOKE_ENCODING")
    def test_12_unrecognized_format_custom(self):
        x=method(invoke(op=0xfc))
        self.assertEqual(p297.category(x,x,self.a,self.b),
                         "UNSUPPORTED_INVOKE_ENCODING")
    def test_13_malformed_length(self):
        x=method(Ins("invoke-static",b"\x71\x10\x01\x00",()))
        self.assertIsNone(p297.raw_invokes(x))
    def test_14_no_instruction_api(self):
        x=method(invoke());x.get_instructions_idx=lambda:1//0
        self.assertIsNone(p297.raw_invokes(x))
    def test_15_raw_missing(self):
        x=method(invoke());x.rows[0][1].get_raw=lambda:None
        self.assertIsNone(p297.raw_invokes(x))
    def test_16_missing_pool_api(self):
        self.assertIsNone(p297.resolved(object(),1))
    def test_17_method_reference_format_invalid(self):
        self.assertIsNone(p297.resolved(Pool({1:("bad","hello",("(I)","V"))}),1))
    def test_18_changed_opcode_denied_as_layout(self):
        self.assertEqual(p297.category(method(invoke(0x71)),method(invoke(0x70)),self.a,self.b),
                         "INSTRUCTION_LAYOUT_UNVERIFIED")
    def test_19_changed_width_denied_as_layout(self):
        a=method(invoke());b=method(Ins("invoke-static",b"\x71\x00\x01\x00",()))
        self.assertEqual(p297.category(a,b,self.a,self.b),
                         "INSTRUCTION_LAYOUT_UNVERIFIED")
    def test_20_counter_bad_total(self):
        q={"count":1,"categories":{k:0 for k in p297.CATEGORIES}}
        with self.assertRaises(Deny):p297.emit(q)
    def test_21_counter_private_extra(self):
        q={"count":1,"categories":{k:0 for k in p297.CATEGORIES}}
        q["categories"]["PRIVATE"]=1
        with self.assertRaises(Deny):p297.emit(q)
    def test_22_counter_negative(self):
        q={"count":1,"categories":{k:0 for k in p297.CATEGORIES}}
        q["categories"][p297.CATEGORIES[0]]=-1
        with self.assertRaises(Deny):p297.emit(q)
    def test_23_emit_always_deny(self):
        q={"count":1,"categories":{k:0 for k in p297.CATEGORIES}}
        q["categories"]["MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE"]=1
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(p297.emit(q),2)
        self.assertIn("P297_RELEASE=DENY",buf.getvalue())
        self.assertIn("P297_OTHER_REFERENCE_KINDS=NOT_ATTESTED",buf.getvalue())
        self.assertNotIn("Lsample/Record",buf.getvalue())
    def test_24_audit_requires_p263_count(self):
        a=method(invoke());prior={"unknown":2}
        with patch.object(p297,"diagnose",return_value=prior),\
             patch.object(p297,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}):
            with self.assertRaises(Deny):
                p297.audit({("foo",):a},{("foo",):a},self.a,self.b)
    def test_25_audit_consistent(self):
        a=method(invoke());prior={"unknown":1}
        with patch.object(p297,"diagnose",return_value=prior),\
             patch.object(p297,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}):
            q=p297.audit({("foo",):a},{("foo",):a},self.a,self.b)
        self.assertEqual(q["categories"]["MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE"],1)
    def test_26_malformed_method_pool_item(self):
        self.assertIsNone(p297.resolved(Pool({1:("Lsample/Record;","call","bad")}),1))
    def test_27_no_invoke_is_empty_tuple(self):
        self.assertEqual(p297.raw_invokes(method()), ())
    def test_28_index_is_derived_per_side(self):
        lhs=Pool({4:REF});rhs=Pool({7:REF})
        self.assertEqual(p297.category(method(invoke(index=4)),method(invoke(index=7)),lhs,rhs),
                         "MATCHING_INVOKE_METHOD_TARGETS_CANDIDATE")
    def test_29_bytes_identical_but_method_pool_mismatch(self):
        lhs=Pool({5:REF});rhs=Pool({5:REF_OTHER})
        self.assertEqual(p297.category(method(invoke(index=5)),method(invoke(index=5)),lhs,rhs),
                         "DIFFERENT_INVOKE_METHOD_TARGET")
    def test_30_extended_format_in_second_method_only(self):
        self.assertEqual(p297.category(method(invoke()),method(invoke(0xfc)),self.a,self.b),
                         "INSTRUCTION_LAYOUT_UNVERIFIED")

if __name__=="__main__":unittest.main()
