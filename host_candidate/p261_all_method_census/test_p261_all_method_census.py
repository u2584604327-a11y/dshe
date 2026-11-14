#!/usr/bin/env python3
"""P261 30 all-method corpus and privacy/unknown fail-closed fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family",
              "host_candidate/p259_all_operands"]
from p246_exception_semantics import Deny
from p249_dual_diff import START,HELPER
from test_p253_cfg_ordinal import D,OTHER,base,width,Method,Op
from test_p257_opcode_family import ROp,StubFrame
from test_p259_all_operands import before,after,op,method
from p261_all_method_census import (
    COUNTS,opaque,explicit_branches,method_observation,census,emit,MAX_METHODS
)
class NoCode:
    def get_code(self):return None
def observation(a=None,b=None):
    return method_observation(before() if a is None else a,
                              after() if b is None else b,D,D)
def scan(aa=None,bb=None):
    aa={START:before()} if aa is None else aa
    bb={START:after()} if bb is None else bb
    return census(aa,bb,D,D)
class Tests(unittest.TestCase):
 def test_01_full_first_method_supported_operands(self):
    q=observation()
    self.assertEqual((q["ORIGINAL_CODE_METHODS"],q["OPERANDS_STRUCTURED_MATCH"]),(1,1))
 def test_02_first_size_difference(self):
    self.assertEqual(observation()["CODE_SIZE_CHANGED"],1)
 def test_03_first_opcodes_only_encoding_candidate(self):
    self.assertEqual(observation()["OPCODE_ENCODING_CANDIDATE_ONLY"],1)
 def test_04_no_raw_exception_change(self):
    self.assertEqual(observation()["RAW_EXCEPTION_CHANGED"],0)
 def test_05_no_ordinal_exception_change(self):
    self.assertEqual(observation()["EXCEPTION_ORDINAL_CHANGED"],0)
 def test_06_missing_register_frame_unattested(self):
    self.assertEqual(observation()["FRAME_NOT_ATTESTED"],1)
 def test_07_unchanged_opcode_literal_change_detected(self):
    a=method(op(),op("const/16",4,((0,1),(1,3))),op("return-void",2,()))
    b=method(op("const/16",4),op("const/16",4,((0,1),(1,4))),op("return-void",2,()))
    self.assertEqual(observation(a,b)["OPERANDS_STRUCTURED_DIFFER"],1)
 def test_08_unchanged_opcode_register_change_detected(self):
    b=method(op("const/16",4),op("move",2,((0,2),(0,0))),op("return-void",2,()))
    self.assertEqual(observation(before(),b)["OPERANDS_STRUCTURED_DIFFER"],1)
 def test_09_changed_opcode_operand_mismatch_detected(self):
    b=method(op("const/16",4,((0,0),(1,9))),
             op("move/from16",4,((0,1),(0,0))),op("return-void",2,()))
    self.assertEqual(observation(before(),b)["OPERANDS_STRUCTURED_DIFFER"],1)
 def test_10_opaque_operand_unattested(self):
    a=method(op(),Op("move"),op("return-void",2,()))
    self.assertEqual(observation(a,after())["OPERANDS_NOT_ATTESTED"],1)
 def test_11_unsupported_packed_switch_counted_not_ignored(self):
    a=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    b=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    q=observation(a,b)
    self.assertEqual((q["UNSUPPORTED_PAYLOAD_METHODS"],q["OPERANDS_NOT_ATTESTED"]),(1,1))
 def test_12_unsupported_sparse_switch_counted(self):
    x=method(op("sparse-switch",2,((3,2),)),op("return-void",2,()))
    self.assertEqual(observation(x,x)["UNSUPPORTED_PAYLOAD_METHODS"],1)
 def test_13_unsupported_fill_array_counted(self):
    x=method(op("fill-array-data",2,((3,2),)),op("return-void",2,()))
    self.assertEqual(observation(x,x)["UNSUPPORTED_PAYLOAD_METHODS"],1)
 def test_14_switch_in_only_derived_still_unattested(self):
    a=method(op("move",2,((0,0),(0,1))),op("return-void",2,()))
    b=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    self.assertEqual(observation(a,b)["OPERANDS_NOT_ATTESTED"],1)
 def test_15_count_changed_not_silently_skipped(self):
    b=method(op("const/16",4),op("return-void",2,()))
    q=observation(before(),b)
    self.assertEqual((q["OPCODE_COUNT_CHANGED"],q["OPERANDS_NOT_ATTESTED"]),(1,1))
 def test_16_kind_changed_and_operand_diff(self):
    a=method(op("add-int",4,((0,0),)),op("return-void",2,()))
    b=method(op("sub-int",4,((0,0),)),op("return-void",2,()))
    q=observation(a,b)
    self.assertEqual((q["OPCODE_OPERATION_KIND_CHANGED"],q["OPERANDS_STRUCTURED_DIFFER"]),(1,1))
 def test_17_same_size_same_opcode_valid_match(self):
    q=observation(before(),before())
    self.assertEqual((q["CODE_SIZE_CHANGED"],q["OPERANDS_STRUCTURED_MATCH"]),(0,1))
 def test_18_explicit_goto_width_promoted_same_target(self):
    a=method(op("goto",2,((3,2),),2),op("nop",2,()),op("return-void",2,()))
    b=method(op("goto/16",4,((3,3),),3),op("nop",2,()),op("return-void",2,()))
    q=observation(a,b)
    self.assertEqual((q["BRANCH_SIGNATURE_CHANGED"],q["OPERANDS_STRUCTURED_MATCH"]),(0,1))
 def test_19_explicit_goto_real_wrong_target(self):
    a=method(op("goto",2,((3,2),),2),op("nop",2,()),op("return-void",2,()))
    b=method(op("goto/16",4,((3,2),),2),op("nop",2,()),op("return-void",2,()))
    self.assertEqual(observation(a,b)["BRANCH_SIGNATURE_CHANGED"],1)
 def test_20_if_branch_register_changed(self):
    a=method(op("if-eqz",4,((0,0),(3,3)),3),op("nop",2,()),op("return-void",2,()))
    b=method(op("if-eqz",4,((0,1),(3,3)),3),op("nop",2,()),op("return-void",2,()))
    self.assertEqual(observation(a,b)["OPERANDS_STRUCTURED_DIFFER"],1)
 def test_21_frame_different_detected(self):
    a,b=before(),after()
    a.code=StubFrame(a.code,(8,2,3));b.code=StubFrame(b.code,(8,2,4))
    self.assertEqual(observation(a,b)["FRAME_CHANGED"],1)
 def test_22_frame_match(self):
    a,b=before(),after()
    a.code=StubFrame(a.code,(8,2,3));b.code=StubFrame(b.code,(8,2,3))
    self.assertEqual(observation(a,b)["FRAME_NOT_ATTESTED"],0)
 def test_23_all_original_methods_scanned(self):
    x=scan({START:before(),OTHER:before()},{START:after(),OTHER:before()})
    self.assertEqual((x["ORIGINAL_CODE_METHODS"],x["CODE_SIZE_CHANGED"],
                      x["OPERANDS_STRUCTURED_MATCH"]),(2,1,2))
 def test_24_no_code_methods_excluded_from_code_count(self):
    x=scan({START:before(),OTHER:NoCode()},{START:after(),OTHER:NoCode()})
    self.assertEqual(x["ORIGINAL_CODE_METHODS"],1)
 def test_25_original_helper_only_is_allowed_extra(self):
    q=scan({START:before()},{START:after(),HELPER:before()})
    self.assertEqual(q["ORIGINAL_CODE_METHODS"],1)
 def test_26_unapproved_added_method_denied(self):
    with self.assertRaises(Deny):
        scan({START:before()},{START:after(),OTHER:before()})
 def test_27_deleted_method_denied(self):
    with self.assertRaises(Deny):
        scan({START:before(),OTHER:before()},{START:after()})
 def test_28_second_method_diff_not_ignored(self):
    x=scan({START:before(),OTHER:before()},{START:after(),OTHER:after()})
    self.assertEqual(x["CODE_SIZE_CHANGED"],2)
 def test_29_unsupported_second_method_counted(self):
    unsupported=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    q=scan({START:before(),OTHER:unsupported},
           {START:after(),OTHER:unsupported})
    self.assertEqual((q["ORIGINAL_CODE_METHODS"],q["UNSUPPORTED_PAYLOAD_METHODS"],
                      q["OPERANDS_NOT_ATTESTED"]),(2,1,1))
 def test_30_exception_raw_vs_ordinal_separate(self):
    a,b=base(),width()
    q=observation(a,b)
    self.assertEqual((q["RAW_EXCEPTION_CHANGED"],q["EXCEPTION_ORDINAL_CHANGED"]),(1,0))
 def test_31_exception_ordinal_real_difference(self):
    a=base();b=width()
    # Same valid target ordinal? change handler to a different instruction.
    b.code.table.entries[0].pairs[0].addr=6
    self.assertEqual(observation(a,b)["EXCEPTION_ORDINAL_CHANGED"],1)
 def test_32_public_counters_sanitized_and_never_release(self):
    v=scan()
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        self.assertEqual(emit(v),2)
    out=buf.getvalue()
    self.assertNotIn(START[0],out)
    self.assertIn("P261_RELEASE=DENY",out)
    self.assertIn("P261_SCOPE=ALL_ORIGINAL_CODE_METHODS",out)
 def test_33_wrong_counter_schema_denied(self):
    v=scan();v["PRIVATE_METHOD"]=1
    with self.assertRaises(Deny):emit(v)
 def test_34_broken_total_coverage_denied(self):
    v=scan();v["OPERANDS_STRUCTURED_MATCH"]=0
    with self.assertRaises(Deny):emit(v)
 def test_35_integer_count_bounds_denied(self):
    v=scan();v["OPERANDS_NOT_ATTESTED"]=MAX_METHODS+1
    with self.assertRaises(Deny):emit(v)
 def test_36_no_original_code_denied(self):
    with self.assertRaises(Deny):
        scan({START:NoCode()},{START:NoCode()})
if __name__=="__main__":unittest.main()
