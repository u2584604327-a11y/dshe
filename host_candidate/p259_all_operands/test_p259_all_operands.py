#!/usr/bin/env python3
"""P259 38 source-only adversarial whole-method operand coverage fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family"]
from p246_exception_semantics import Deny
from p249_dual_diff import START
from test_p253_cfg_ordinal import D,OTHER,Method,Op
from test_p257_opcode_family import ROp,StubFrame,BrokenROp
from p259_all_operands import operands,pair,aggregate,inspect_pair,audit,emit

def op(name="const/4",width=2,args=((0,0),(1,7)),off=0):
    return ROp(name,width,args,off)
def method(*items):
    return Method(ops=list(items),tries=[])
def before():
    return method(op(),op("move",2,((0,1),(0,0))),
                  op("return-void",2,()))
def after():
    return method(op("const/16",4),op("move/from16",4,((0,1),(0,0))),
                  op("return-void",2,()))
def inspect(a=None,b=None):
    return inspect_pair(before() if a is None else a,
                        after() if b is None else b,D,D)
def audit_pair(a=None,b=None,key=START):
    return audit({key:before() if a is None else a},
                 {key:after() if b is None else b},D,D)

class Tests(unittest.TestCase):
 def test_01_all_operands_match(self):
    q=inspect()
    self.assertEqual((q["total"],q["unchanged"],q["changed"]),
                     ("STRUCTURED_MATCH","STRUCTURED_MATCH","STRUCTURED_MATCH"))
 def test_02_changed_opcode_operands_differ(self):
    b=method(op("const/16",4,((0,0),(1,8))),
             op("move/from16",4,((0,1),(0,0))),op("return-void",2,()))
    self.assertEqual(inspect(b=b)["changed"],"STRUCTURED_DIFFER")
 def test_03_unchanged_opcode_different_literal(self):
    a=method(op(),op("const/16",4,((0,1),(1,15))),op("return-void",2,()))
    b=method(op("const/16",4),op("const/16",4,((0,1),(1,16))),op("return-void",2,()))
    q=inspect(a,b)
    self.assertEqual((q["unchanged"],q["total"]),
                     ("STRUCTURED_DIFFER","STRUCTURED_DIFFER"))
 def test_04_unchanged_opcode_different_register(self):
    a=method(op(),op("move",2,((0,1),(0,0))),op("return-void",2,()))
    b=method(op("const/16",4),op("move",2,((0,2),(0,0))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["unchanged"],"STRUCTURED_DIFFER")
 def test_05_same_opcode_all_operand_mismatch(self):
    a=method(op("const/4",2,((0,0),(1,2))),op("return-void",2,()))
    b=method(op("const/4",2,((0,0),(1,3))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"STRUCTURED_DIFFER")
 def test_06_unresolvable_operand_not_attested(self):
    a=method(op(),Op("move"),op("return-void",2,()))
    q=inspect(a,after())
    self.assertEqual((q["total"],q["unchanged"]),("NOT_ATTESTED","STRUCTURED_MATCH"))
 def test_07_missing_api_in_unchanged_opcode(self):
    a=method(op(),op("move",2,((0,1),(0,0))),Op("return-void"))
    self.assertEqual(inspect(a,after())["unchanged"],"NOT_ATTESTED")
 def test_08_unreadable_operand_at_changed_opcode(self):
    a=method(BrokenROp("const/4",2),op("return-void",2,()))
    b=method(op("const/16",4),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["changed"],"NOT_ATTESTED")
 def test_09_public_sanitized_never_leak_exception(self):
    a=method(BrokenROp("const/4",2),op("return-void",2,()))
    b=method(op("const/16",4),op("return-void",2,()))
    q=inspect(a,b)
    self.assertEqual(q["total"],"NOT_ATTESTED")
 def test_10_opaque_reference_unattested(self):
    a=method(op("const-string",4,((0,0),(260,7))),op("return-void",2,()))
    b=method(op("const-string/jumbo",6,((0,0),(260,7))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"NOT_ATTESTED")
 def test_11_reference_pool_reindex_normalized(self):
    a=method(op("const-string",4,((0,0),(260,7,"same_string"))),op("return-void",2,()))
    b=method(op("const-string/jumbo",6,((0,0),(260,77,"same_string"))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"STRUCTURED_MATCH")
 def test_12_reference_symbol_change_detected(self):
    a=method(op("const-string",4,((0,0),(260,7,"original"))),op("return-void",2,()))
    b=method(op("const-string/jumbo",6,((0,0),(260,7,"changed"))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"STRUCTURED_DIFFER")
 def test_13_same_opcode_reference_changed(self):
    a=method(op("const-string",4,((0,0),(260,1,"A"))),op("return-void",2,()))
    b=method(op("const-string",4,((0,0),(260,1,"B"))),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["unchanged"],"STRUCTURED_DIFFER")
 def test_14_unexpected_raw_operand_denied(self):
    self.assertIsNone(operands(op("const/4",2,((2,777),)),"const/4"))
 def test_15_nonbranch_offset_denied(self):
    self.assertIsNone(operands(op("move",2,((3,2),)),"move"))
 def test_16_branch_target_offset_normalized(self):
    a=op("goto",2,((3,2),),2)
    b=op("goto/16",4,((3,3),),3)
    self.assertEqual((operands(a,"goto"),operands(b,"goto/16")),((),()))
 def test_17_branch_target_real_signature_valid(self):
    a=method(op("goto",2,((3,2),),2),op("nop",2,()),op("return-void",2,()))
    b=method(op("goto/16",4,((3,3),),3),op("nop",2,()),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"STRUCTURED_MATCH")
 def test_18_branch_register_change_detected(self):
    a=method(op("if-eqz",4,((0,0),(3,4)),2),op("nop",2,()),op("return-void",2,()))
    b=method(op("if-eqz",4,((0,1),(3,4)),2),op("nop",2,()),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["total"],"STRUCTURED_DIFFER")
 def test_19_branch_register_keep_target_offset_shift(self):
    a=op("if-eqz",4,((0,0),(3,2)),2)
    b=op("if-eqz",4,((0,0),(3,3)),3)
    self.assertEqual(operands(a,"if-eqz"),operands(b,"if-eqz"))
 def test_20_branch_two_offsets_unattested(self):
    self.assertIsNone(operands(op("goto",2,((3,2),(3,2))),"goto"))
 def test_21_branch_no_offset_unattested(self):
    self.assertIsNone(operands(op("goto",2,()),"goto"))
 def test_22_branch_missing_api_unattested(self):
    self.assertIsNone(operands(Op("goto",2,2),"goto"))
 def test_23_register_tag_boolean_not_index(self):
    self.assertIsNone(operands(op("move",2,((0,True),)),"move"))
 def test_24_bad_literal_type_unattested(self):
    self.assertIsNone(operands(op("const/4",2,((1,"7"),)),"const/4"))
 def test_25_bad_reference_type_unattested(self):
    self.assertIsNone(operands(op("const-string",4,((260,2,b"raw"),)),"const-string"))
 def test_26_really_different_operation_kind_differ(self):
    a=method(op("add-int",4,((0,0),)),op("return-void",2,()))
    b=method(op("sub-int",4,((0,0),)),op("return-void",2,()))
    self.assertEqual(inspect(a,b)["changed"],"STRUCTURED_DIFFER")
 def test_27_instruction_count_mismatch_hard_deny(self):
    a=before();b=method(op("const/16",4),op("return-void",2,()))
    q=inspect(a,b)
    self.assertEqual((q["total"],q["unchanged"],q["changed"]),
                     ("COUNT_CHANGED","COUNT_CHANGED","COUNT_CHANGED"))
 def test_28_no_changed_opcodes(self):
    q=inspect(before(),before())
    self.assertEqual((q["total"],q["changed"]),
                     ("STRUCTURED_MATCH","NOT_APPLICABLE"))
 def test_29_unknown_supersedes_match(self):
    self.assertEqual(aggregate(["STRUCTURED_MATCH","NOT_ATTESTED"]),"NOT_ATTESTED")
 def test_30_difference_supersedes_unknown(self):
    self.assertEqual(aggregate(["NOT_ATTESTED","STRUCTURED_DIFFER"]),"STRUCTURED_DIFFER")
 def test_31_all_matching_aggregation(self):
    self.assertEqual(aggregate(["STRUCTURED_MATCH"]*3),"STRUCTURED_MATCH")
 def test_32_empty_aggregation(self):
    self.assertEqual(aggregate([]),"NOT_APPLICABLE")
 def test_33_actual_first_method_group(self):
    self.assertEqual(audit_pair()["group"],"START_COROUTINE")
 def test_34_other_first_method_group(self):
    self.assertEqual(audit_pair(key=OTHER)["group"],"OTHER_PRIMARY")
 def test_35_no_size_method_no_verification_claim(self):
    q=audit_pair(before(),before())
    self.assertEqual(q["total"],"NOT_APPLICABLE")
 def test_36_public_report_sanitized_and_denied(self):
    q=audit_pair()
    out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(emit(q),2)
    s=out.getvalue()
    self.assertNotIn(START[0],s)
    self.assertIn("P259_SCOPE=FIRST_SIZE_METHOD_ONLY",s)
    self.assertIn("P259_ALL_OTHER_ORIGINAL_METHODS=NOT_ATTESTED",s)
    self.assertIn("P259_UNCHANGED_P245_FULL_GATE=NOT_ATTESTED",s)
 def test_37_public_enum_spoof_rejected(self):
    q=audit_pair();q["total"]="FULLY_SAFE"
    with self.assertRaises(Deny):emit(q)
 def test_38_unknown_switch_payload_fail_closed(self):
    a=method(op(),op("return-void",2,()))
    b=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    with self.assertRaises(Deny):inspect(a,b)
if __name__=="__main__":unittest.main()
