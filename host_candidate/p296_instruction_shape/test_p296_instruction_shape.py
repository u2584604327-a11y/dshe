#!/usr/bin/env python3
"""P296 independent adversarial tests: no raw DEX claims, no production gate."""
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
    "host_candidate/p295_raw_unknowns",
]
from p246_exception_semantics import Deny
from test_p295_raw_unknowns import Ins, Method, sample
import p296_instruction_shape as p296

def method(name="const/4", data=b"\x12\x00", operands=((0, 0), (1, 0))):
    return Method(Ins(name, data, operands), Ins())

def indexed(ref="A", value=1):
    return method("const-string", b"\x1a\x00\x00\x00",
                  ((0, 0), (260, value, ref)))

def report(count=1, group="OPERAND_FORMAT", shape="RAW_EXACT", ref="UNVERIFIED"):
    a={k:0 for k in p296.FIELDS}
    b={k:0 for k in p296.REFERENCE_FIELDS}
    if count:
        a[group+"_"+shape]=count
        b[ref]=count
    return {"count":count,"shapes":a,"refs":b}

class Cases(unittest.TestCase):
    def test_01_exact(self):
        self.assertEqual(p296.encoded_shape(sample(),sample()),"RAW_EXACT")
    def test_02_different_instruction_count(self):
        self.assertEqual(p296.encoded_shape(sample(),Method(Ins())),
                         "RAW_DIFFER_COUNT")
    def test_03_width_changed(self):
        self.assertEqual(p296.encoded_shape(method(),method(data=b"\x12\x00\x00\x00")),
                         "RAW_DIFFER_WIDTH")
    def test_04_opcode_changed_same_width(self):
        self.assertEqual(p296.encoded_shape(method(),method(name="move")),
                         "RAW_DIFFER_OPCODE")
    def test_05_same_opcode_width_but_raw_diff(self):
        self.assertEqual(p296.encoded_shape(method(),method(data=b"\x12\x01")),
                         "RAW_DIFFER_SAME_SHAPE")
    def test_06_unreadable_raw(self):
        x=method();x.rows[0][1].get_raw=lambda:None
        self.assertEqual(p296.encoded_shape(x,method()),"RAW_UNREADABLE")
    def test_07_reference_visible_exact(self):
        self.assertEqual(p296.reference_category(indexed(),indexed()),
                         "DISPLAY_MATCH_ONLY")
    def test_08_reference_label_diff(self):
        self.assertEqual(p296.reference_category(indexed("one"),indexed("two")),
                         "DISPLAY_DIFFER")
    def test_09_reference_index_shift_same_display(self):
        self.assertEqual(p296.reference_category(indexed("one",1),indexed("one",4)),
                         "DISPLAY_MATCH_ONLY")
    def test_10_reference_no_visible(self):
        self.assertEqual(p296.reference_category(method(),method()),
                         "NO_VISIBLE_INDEX_REFERENCES")
    def test_11_reference_missing_api(self):
        x=method();x.rows[0][1].get_operands=None
        self.assertEqual(p296.reference_category(x,method()),"UNVERIFIED")
    def test_12_reference_bad_kind(self):
        x=method(operands=((17,0),))
        self.assertIsNone(p296.reference_display(x))
    def test_13_reference_bad_value(self):
        x=method(operands=((260,-1,"A"),))
        self.assertIsNone(p296.reference_display(x))
    def test_14_reference_missing_display(self):
        x=method(operands=((260,1),))
        self.assertIsNone(p296.reference_display(x))
    def test_15_reference_empty_display(self):
        x=method(operands=((260,1,""),))
        self.assertIsNone(p296.reference_display(x))
    def test_16_reference_oversize_display(self):
        x=method(operands=((260,1,"x"*8193),))
        self.assertIsNone(p296.reference_display(x))
    def test_17_reference_bad_index_type(self):
        x=method(operands=((260,True,"A"),))
        self.assertIsNone(p296.reference_display(x))
    def test_18_reference_bad_tag_type(self):
        x=method(operands=((True,0),))
        self.assertIsNone(p296.reference_display(x))
    def test_19_reference_getter_exception(self):
        x=method();x.rows[0][1].get_operands=lambda:1//0
        self.assertIsNone(p296.reference_display(x))
    def test_20_reference_display_format_not_canonical(self):
        self.assertEqual(p296.reference_category(indexed("A B"),indexed("AB")),
                         "DISPLAY_DIFFER")
    def test_21_emit_deny_even_when_no_mismatches(self):
        q=report()
        b=io.StringIO()
        with contextlib.redirect_stdout(b):
            self.assertEqual(p296.emit(q),2)
        self.assertIn("P296_RELEASE=DENY",b.getvalue())
        self.assertIn("P296_RAW_EXACT_METHODS_POOL_TARGET_IDENTITY=NOT_ATTESTED",b.getvalue())
    def test_22_emit_zero_count_deny(self):
        self.assertEqual(p296.emit(report(0)),2)
    def test_23_emit_forged_extra_schema(self):
        q=report();q["secret"]="private"
        with self.assertRaises(Deny):p296.emit(q)
    def test_24_emit_forged_shape_counter(self):
        q=report();q["shapes"]["OPERAND_FORMAT_RAW_EXACT"]=2
        with self.assertRaises(Deny):p296.emit(q)
    def test_25_emit_forged_ref_counter(self):
        q=report();q["refs"]["UNVERIFIED"]=2
        with self.assertRaises(Deny):p296.emit(q)
    def test_26_emit_negative_count(self):
        q=report();q["refs"]["UNVERIFIED"]=-1
        with self.assertRaises(Deny):p296.emit(q)
    def test_27_output_privacy(self):
        q=report()
        b=io.StringIO()
        with contextlib.redirect_stdout(b):p296.emit(q)
        self.assertNotIn("EngineManager",b.getvalue())
        self.assertNotIn("Landroid/util/Log;",b.getvalue())
    def test_28_audit_reconciles_prior_group(self):
        m=method()
        prior={"unknown":1,"counts":{
            "UNKNOWN_PAYLOAD":0,"UNKNOWN_INSTRUCTION_COUNT":0,
            "UNKNOWN_OPERAND_FORMAT":1,"UNKNOWN_OTHER":0}}
        with patch.object(p296,"diagnose",return_value=prior),\
             patch.object(p296,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p296,"reason",return_value="OPERAND_FORMAT"):
            q=p296.audit({("A",):m},{("A",):m},None,None)
        self.assertEqual(q["count"],1)
        self.assertEqual(q["shapes"]["OPERAND_FORMAT_RAW_EXACT"],1)
    def test_29_audit_misclassified_group_denied(self):
        m=method()
        prior={"unknown":1,"counts":{
            "UNKNOWN_PAYLOAD":1,"UNKNOWN_INSTRUCTION_COUNT":0,
            "UNKNOWN_OPERAND_FORMAT":0,"UNKNOWN_OTHER":0}}
        with patch.object(p296,"diagnose",return_value=prior),\
             patch.object(p296,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p296,"reason",return_value="OPERAND_FORMAT"):
            with self.assertRaises(Deny):
                p296.audit({("A",):m},{("A",):m},None,None)
    def test_30_audit_unknown_category_denied(self):
        m=method()
        prior={"unknown":1,"counts":{
            "UNKNOWN_PAYLOAD":1,"UNKNOWN_INSTRUCTION_COUNT":0,
            "UNKNOWN_OPERAND_FORMAT":0,"UNKNOWN_OTHER":0}}
        with patch.object(p296,"diagnose",return_value=prior),\
             patch.object(p296,"method_observation",return_value={"OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p296,"reason",return_value="INVALID"):
            with self.assertRaises(Deny):
                p296.audit({("A",):m},{("A",):m},None,None)

if __name__=="__main__":unittest.main()
