#!/usr/bin/env python3
"""P295 adversarial source tests. Real original DEX must be checked separately."""
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
]
from p246_exception_semantics import Deny
import p295_raw_unknowns as p295

class Code:
    def __init__(self, units, tries=()):
        self.units, self.tries = units, list(tries)
    def get_insns_size(self):return self.units
    def get_tries(self):return self.tries
    def get_tries_size(self):return len(self.tries)
    def get_handlers(self):return None

class Ins:
    def __init__(self, name="return-void", data=b"\x0e\x00", operands=()):
        self.name, self.data, self.ops = name, data, operands
    def get_name(self):return self.name
    def get_length(self):return len(self.data)
    def get_raw(self):return self.data
    def get_operands(self):return self.ops

class Method:
    def __init__(self, *ops, units=None):
        self.rows=[]
        p=0
        for op in ops:
            self.rows.append((p,op))
            p+=op.get_length()
        self.code=Code(p//2 if units is None else units)
    def get_code(self):return self.code
    def get_instructions_idx(self):return iter(self.rows)

def sample():
    return Method(Ins("const/4",b"\x12\x00",((0,0),(1,0))),
                  Ins("return-void",b"\x0e\x00",()))

class Tests(unittest.TestCase):
    def test_01_exact_raw(self):
        self.assertEqual(p295.raw_comparison(sample(),sample()),"EXACT_BYTES_ONLY")
    def test_02_changed_literal(self):
        self.assertEqual(p295.raw_comparison(sample(),
                         Method(Ins("const/4",b"\x12\x01"),Ins())),"DIFFERENT_BYTES")
    def test_03_same_size_changed_opcode(self):
        self.assertEqual(p295.raw_comparison(sample(),
                         Method(Ins("move",b"\x01\x00"),Ins())),"DIFFERENT_BYTES")
    def test_04_missing_get_raw(self):
        x=sample();x.rows[0]=(0,object())
        self.assertEqual(p295.raw_comparison(x,sample()),"UNREADABLE")
    def test_05_get_raw_not_bytes(self):
        x=sample();x.rows[0][1].get_raw=lambda:bytearray(b"\x12\x00")
        self.assertIsNone(p295.instruction_bytes(x))
    def test_06_truncated_raw(self):
        x=sample();x.rows[0][1].get_raw=lambda:b"\x12"
        self.assertIsNone(p295.instruction_bytes(x))
    def test_07_oversized_raw(self):
        x=sample();x.rows[0][1].get_raw=lambda:b"\x12\x00\x00"
        self.assertIsNone(p295.instruction_bytes(x))
    def test_08_missing_instruction(self):
        x=sample();x.rows=x.rows[:-1]
        self.assertIsNone(p295.instruction_bytes(x))
    def test_09_duplicate_pc(self):
        x=sample();x.rows[1]=(0,x.rows[1][1])
        self.assertIsNone(p295.instruction_bytes(x))
    def test_10_gap_in_pc(self):
        x=sample();x.rows[1]=(4,x.rows[1][1])
        self.assertIsNone(p295.instruction_bytes(x))
    def test_11_odd_pc(self):
        x=sample();x.rows[1]=(3,x.rows[1][1])
        self.assertIsNone(p295.instruction_bytes(x))
    def test_12_declared_code_size_wrong(self):
        x=sample();x.code=Code(9)
        self.assertIsNone(p295.instruction_bytes(x))
    def test_13_odd_instruction_width(self):
        x=sample();x.rows[0][1].get_length=lambda:3
        self.assertIsNone(p295.instruction_bytes(x))
    def test_14_zero_instruction_width(self):
        x=sample();x.rows[0][1].get_length=lambda:0
        self.assertIsNone(p295.instruction_bytes(x))
    def test_15_get_raw_throws(self):
        x=sample();x.rows[0][1].get_raw=lambda:1//0
        self.assertIsNone(p295.instruction_bytes(x))
    def test_16_payload_category_with_same_raw(self):
        x=Method(Ins("packed-switch",b"\x2b\x00"),Ins())
        self.assertEqual(p295.classify(x,x,None,None),
                         "UNKNOWN_PAYLOAD_EXACT_BYTES_ONLY")
    def test_17_payload_changed_bytes(self):
        a=Method(Ins("fill-array-data",b"\x26\x00"),Ins())
        b=Method(Ins("fill-array-data",b"\x26\x10"),Ins())
        self.assertEqual(p295.classify(a,b,None,None),
                         "UNKNOWN_PAYLOAD_DIFFERENT_BYTES")
    def test_18_opaque_operand_format_category(self):
        x=sample();x.rows[0][1].get_operands=lambda:None
        self.assertEqual(p295.reason(x,x,None,None),"OPERAND_FORMAT")
    def test_19_inaccessible_operand_unreadable_raw(self):
        x=sample();x.rows[0][1].get_operands=lambda:None
        x.rows[0][1].get_raw=lambda:None
        self.assertEqual(p295.classify(x,x,None,None),
                         "UNKNOWN_OPERAND_FORMAT_UNREADABLE")
    def test_20_instruction_count_category(self):
        a=sample();b=Method(Ins("return-void",b"\x0e\x00"),
                            Ins("return-void",b"\x0e\x00"),
                            Ins("return-void",b"\x0e\x00"))
        self.assertEqual(p295.reason(a,b,None,None),"INSTRUCTION_COUNT")
    def test_21_empty_code_refused(self):
        self.assertIsNone(p295.instruction_bytes(Method()))
    def test_22_oversized_code_refused(self):
        x=sample();x.code=Code(p295.LIMIT+1)
        self.assertIsNone(p295.instruction_bytes(x))
    def test_23_emit_enforces_deny_and_privacy(self):
        counts={k:0 for k in p295.FIELDS}
        counts["UNKNOWN_OPERAND_FORMAT_EXACT_BYTES_ONLY"]=1
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(p295.emit({"counts":counts,"total":1}),2)
        s=buf.getvalue()
        self.assertIn("P295_RELEASE=DENY",s)
        self.assertIn("P295_REFERENCE_POOL_TARGETS=NOT_ATTESTED",s)
        self.assertNotIn("EngineManager$start$2",s)
    def test_24_forged_private_schema_denied(self):
        counts={k:0 for k in p295.FIELDS};counts["PRIVATE"]=1
        with self.assertRaises(Deny):p295.emit({"counts":counts,"total":1})
    def test_25_forged_total_denied(self):
        with self.assertRaises(Deny):
            p295.emit({"counts":{k:0 for k in p295.FIELDS},"total":1})
    def test_26_negative_count_denied(self):
        x={k:0 for k in p295.FIELDS};x[p295.FIELDS[0]]=-1
        with self.assertRaises(Deny):p295.emit({"counts":x,"total":0})
    def test_27_unsupported_extra_method_not_silent(self):
        a=sample()
        with patch.object(p295,"diagnose",return_value={"unknown":1,"counts":{
             "UNKNOWN_PAYLOAD":0,"UNKNOWN_INSTRUCTION_COUNT":0,
             "UNKNOWN_OPERAND_FORMAT":1,"UNKNOWN_OTHER":0}}),\
             patch.object(p295,"method_observation",return_value={
             "OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p295,"classify",return_value="UNKNOWN_PAYLOAD_EXACT_BYTES_ONLY"):
            with self.assertRaises(Deny):
                p295.audit({("a",):a},{("a",):a},None,None)
    def test_28_aggregate_counters_reconciled(self):
        a=sample()
        with patch.object(p295,"diagnose",return_value={"unknown":1,"counts":{
             "UNKNOWN_PAYLOAD":1,"UNKNOWN_INSTRUCTION_COUNT":0,
             "UNKNOWN_OPERAND_FORMAT":0,"UNKNOWN_OTHER":0}}),\
             patch.object(p295,"method_observation",return_value={
             "OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p295,"classify",return_value="UNKNOWN_PAYLOAD_EXACT_BYTES_ONLY"):
            report=p295.audit({("a",):a},{("a",):a},None,None)
            self.assertEqual(report["total"],1)
    def test_29_undercount_denied(self):
        a=sample()
        with patch.object(p295,"diagnose",return_value={"unknown":1,"counts":{
             "UNKNOWN_PAYLOAD":1,"UNKNOWN_INSTRUCTION_COUNT":0,
             "UNKNOWN_OPERAND_FORMAT":0,"UNKNOWN_OTHER":0}}),\
             patch.object(p295,"method_observation",return_value={
             "OPERANDS_NOT_ATTESTED":0}):
            with self.assertRaises(Deny):
                p295.audit({("a",):a},{("a",):a},None,None)
    def test_30_invalid_result_category_denied(self):
        a=sample()
        with patch.object(p295,"diagnose",return_value={"unknown":1,"counts":{
             "UNKNOWN_PAYLOAD":1,"UNKNOWN_INSTRUCTION_COUNT":0,
             "UNKNOWN_OPERAND_FORMAT":0,"UNKNOWN_OTHER":0}}),\
             patch.object(p295,"method_observation",return_value={
             "OPERANDS_NOT_ATTESTED":1}),\
             patch.object(p295,"classify",return_value="UNKNOWN_PAYLOAD_APPROVED"):
            with self.assertRaises(Deny):
                p295.audit({("a",):a},{("a",):a},None,None)

if __name__=="__main__":unittest.main()
