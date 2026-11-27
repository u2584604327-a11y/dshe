#!/usr/bin/env python3
"""P257 36 source-only opcode/operand negative cases; no real APK inputs."""
import contextlib,enum,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
             "host_candidate/p249_dual_diff",
             "host_candidate/p251_method_relation",
             "host_candidate/p253_cfg_ordinal",
             "host_candidate/p255_branch_separation"]
from p246_exception_semantics import Deny
from test_p253_cfg_ordinal import D,START,OTHER,NAMES,Op,Method,base,wrong_jump
from p257_opcode_family import (
  encoding_candidate,normalized_operands,frame,inspect_pair,audit,emit
)
class ROp(Op):
    def __init__(self,name,width=2,operands=(),off=0):
        super().__init__(name,width,off)
        self.operands=operands
    def get_operands(self):return self.operands
class BrokenROp(ROp):
    def get_operands(self):raise RuntimeError("SENSITIVE_STRING_DO_NOT_PRINT")
class StubFrame:
    def __init__(self,other,values):
        self.inner=other
        self.values=values
    def __getattr__(self,k):return getattr(self.inner,k)
    def get_registers_size(self):return self.values[0]
    def get_ins_size(self):return self.values[1]
    def get_outs_size(self):return self.values[2]

def one(op):
    return Method(ops=[op,Op("return-void")],tries=[])
def compare(x=None,y=None):
    return inspect_pair(one(x or ROp("const/4",2,((0,0),(1,7)))),
                        one(y or ROp("const/16",4,((0,0),(1,7)))),D,D)
def audit_pair(x=None,y=None,key=START):
    return audit({key:one(x or ROp("const/4",2,((0,0),(1,7))))},
                 {key:one(y or ROp("const/16",4,((0,0),(1,7))))},D,D)
class OperandTag(enum.IntEnum):
    REGISTER=0
    LITERAL=1
    KIND_METH=260
class Tests(unittest.TestCase):
 def test_01_explicit_const_family(self):
    q=compare()
    self.assertEqual((q["first"],q["all"],q["operands"]),
                     ("ENCODING_FAMILY_CANDIDATE","ONLY_ENCODING_CANDIDATES","STRUCTURED_MATCH"))
 def test_02_literal_changed(self):
    q=compare(y=ROp("const/16",4,((0,0),(1,8))))
    self.assertEqual(q["operands"],"STRUCTURED_DIFFER")
 def test_03_register_changed(self):
    q=compare(y=ROp("const/16",4,((0,1),(1,7))))
    self.assertEqual(q["operands"],"STRUCTURED_DIFFER")
 def test_04_negative_literal_preserved(self):
    q=compare(ROp("const/4",2,((0,0),(1,-3))),
              ROp("const/16",4,((0,0),(1,-3))))
    self.assertEqual(q["operands"],"STRUCTURED_MATCH")
 def test_05_intenum_tags_supported(self):
    q=compare(ROp("const/4",2,((OperandTag.REGISTER,0),(OperandTag.LITERAL,7))),
              ROp("const/16",4,((OperandTag.REGISTER,0),(OperandTag.LITERAL,7))))
    self.assertEqual(q["operands"],"STRUCTURED_MATCH")
 def test_06_const_pool_index_remap_but_same_symbol(self):
    a=ROp("const-string",4,((0,0),(260,10,"SafeSyntheticText")))
    b=ROp("const-string/jumbo",6,((0,0),(260,999,"SafeSyntheticText")))
    self.assertEqual(compare(a,b)["operands"],"STRUCTURED_MATCH")
 def test_07_const_pool_symbol_changes(self):
    a=ROp("const-string",4,((0,0),(260,10,"SafeSyntheticText")))
    b=ROp("const-string/jumbo",6,((0,0),(260,10,"DIFFERENT")))
    self.assertEqual(compare(a,b)["operands"],"STRUCTURED_DIFFER")
 def test_08_reference_requires_resolved_symbol(self):
    a=ROp("const-string",4,((0,0),(260,10)))
    b=ROp("const-string/jumbo",6,((0,0),(260,10)))
    self.assertEqual(compare(a,b)["operands"],"NOT_ATTESTED")
 def test_09_missing_operand_api_not_attested(self):
    q=compare(one_op := None,ROp("const/16",4,((0,0),(1,7))))
    self.assertEqual(compare_operand_missing:=inspect_pair(
        one(Op("const/4",2)),one(ROp("const/16",4,((0,0),(1,7)))),D,D)["operands"],"NOT_ATTESTED")
 def test_10_invalid_operand_shape_not_attested(self):
    q=compare(ROp("const/4",2,((0,),)),ROp("const/16",4,((0,0),(1,7))))
    self.assertEqual(q["operands"],"NOT_ATTESTED")
 def test_11_operand_decoder_exception_no_secret_leak(self):
    q=compare(BrokenROp("const/4"),ROp("const/16",4,((0,0),)))
    self.assertEqual(q["operands"],"NOT_ATTESTED")
 def test_12_unknown_raw_operand_unattested(self):
    self.assertEqual(compare(ROp("const/4",2,((2,3),)),ROp("const/16",4,((2,3),)))["operands"],"NOT_ATTESTED")
 def test_13_offset_operand_unattested(self):
    self.assertEqual(compare(ROp("const/4",2,((3,1),)),ROp("const/16",4,((3,1),)))["operands"],"NOT_ATTESTED")
 def test_14_kind_with_invalid_resolved_unattested(self):
    q=compare(ROp("const-string",4,((260,1,""),)),
              ROp("const-string/jumbo",6,((260,1,""),)))
    self.assertEqual(q["operands"],"NOT_ATTESTED")
 def test_15_goto_encoding_delegated_to_branch_audit(self):
    a=one(ROp("goto",2,(),1))
    b=one(ROp("goto/16",4,(),2))
    q=inspect_pair(a,b,D,D)
    self.assertEqual((q["first"],q["operands"]),
                     ("ENCODING_FAMILY_CANDIDATE","BRANCH_TARGETS_DELEGATED"))
 def test_16_move_encoding_candidate(self):
    self.assertEqual(compare(ROp("move",2,((0,1),(0,2))),
                             ROp("move/from16",4,((0,1),(0,2))))["first"],
                     "ENCODING_FAMILY_CANDIDATE")
 def test_17_invoke_encoding_candidate_only(self):
    q=compare(ROp("invoke-static",6,((0,0),(260,5,"SyntheticMethod"))),
              ROp("invoke-static/range",6,((0,0),(260,5,"SyntheticMethod"))))
    self.assertEqual((q["first"],q["operands"]),
                     ("ENCODING_FAMILY_CANDIDATE","STRUCTURED_MATCH"))
 def test_18_operation_kind_changes(self):
    q=compare(ROp("add-int",4,((0,0),)),ROp("mul-int",4,((0,0),)))
    self.assertEqual((q["first"],q["all"]),
                     ("OPERATION_KIND_CHANGED","HAS_OPERATION_KIND_CHANGE"))
 def test_19_similar_prefix_not_a_family(self):
    self.assertFalse(encoding_candidate("if-eq","if-nez"))
 def test_20_cross_family_semantics_changed(self):
    self.assertEqual(compare(ROp("const/4",2,()),ROp("move/16",6,()))["first"],
                     "OPERATION_KIND_CHANGED")
 def test_21_same_opcode_no_classification(self):
    q=compare(ROp("const/4"),ROp("const/4"))
    self.assertEqual((q["first"],q["all"],q["operands"]),
                     ("NONE","NONE","NOT_APPLICABLE"))
 def test_22_same_opcode_width_changed_not_promoted(self):
    q=compare(ROp("const/4",2),ROp("const/4",4))
    self.assertEqual(q["first"],"NONE")
 def test_23_all_opcode_pairs_encoding_candidates(self):
    a=Method(ops=[ROp("const/4",2,((0,0),(1,7))),
                  ROp("move",2,((0,0),(0,1))),Op("return-void")],tries=[])
    b=Method(ops=[ROp("const/16",4,((0,0),(1,7))),
                  ROp("move/from16",4,((0,0),(0,1))),Op("return-void")],tries=[])
    self.assertEqual(inspect_pair(a,b,D,D)["all"],"ONLY_ENCODING_CANDIDATES")
 def test_24_mixed_candidate_and_operation_change(self):
    a=Method(ops=[ROp("const/4",2),ROp("add-int",2),Op("return-void")],tries=[])
    b=Method(ops=[ROp("const/16",4),ROp("sub-int",2),Op("return-void")],tries=[])
    q=inspect_pair(a,b,D,D)
    self.assertEqual((q["first"],q["all"]),
                     ("ENCODING_FAMILY_CANDIDATE","HAS_OPERATION_KIND_CHANGE"))
 def test_25_count_changed_no_false_first_pair(self):
    a=one(ROp("const/4"))
    b=Method(ops=[ROp("const/4"),Op("nop"),Op("return-void")],tries=[])
    q=inspect_pair(a,b,D,D)
    self.assertEqual((q["first"],q["operands"]),("COUNT_CHANGED","NOT_APPLICABLE"))
 def test_26_register_frame_equal(self):
    a,b=one(ROp("const/4")),one(ROp("const/16",4))
    a.code=StubFrame(a.code,(8,2,3));b.code=StubFrame(b.code,(8,2,3))
    self.assertEqual(frame(a,b),"MATCH")
 def test_27_register_frame_different(self):
    a,b=one(ROp("const/4")),one(ROp("const/16",4))
    a.code=StubFrame(a.code,(8,2,3));b.code=StubFrame(b.code,(8,2,4))
    self.assertEqual(frame(a,b),"DIFFER")
 def test_28_register_frame_unknown_not_attested(self):
    self.assertEqual(frame(one(ROp("const/4")),one(ROp("const/16",4))),"NOT_ATTESTED")
 def test_29_invalid_register_frame_denied(self):
    a,b=one(ROp("const/4")),one(ROp("const/16",4))
    a.code=StubFrame(a.code,(8,-1,3));b.code=StubFrame(b.code,(8,2,3))
    with self.assertRaises(Deny):frame(a,b)
 def test_30_audit_first_size_start_group(self):
    self.assertEqual(audit_pair()["group"],"START_COROUTINE")
 def test_31_audit_first_size_other_group(self):
    self.assertEqual(audit_pair(key=OTHER)["group"],"OTHER_PRIMARY")
 def test_32_no_first_size_method(self):
    op=ROp("const/4")
    self.assertEqual(audit_pair(op,op)["group"],"NONE")
 def test_33_public_logs_sanitized_and_blocked(self):
    q=audit_pair(ROp("const-string",4,((0,1),(260,1,"Lsecret;"))),
                 ROp("const-string/jumbo",6,((0,1),(260,100,"Lsecret;"))))
    buffer=io.StringIO()
    with contextlib.redirect_stdout(buffer):
        self.assertEqual(emit(q),2)
    msg=buffer.getvalue()
    self.assertNotIn("Lsecret;",msg)
    self.assertNotIn(START[0],msg)
    self.assertIn("P257_ALL_INSTRUCTION_OPERANDS=NOT_ATTESTED",msg)
    self.assertIn("P257_V139=STRUCTURAL_BLOCKED",msg)
 def test_34_public_enum_spoof_denied(self):
    q=audit_pair();q["first"]="PROVEN_EQUIVALENT"
    with self.assertRaises(Deny):emit(q)
 def test_35_switch_and_payload_fail_closed(self):
    b=Method(ops=[ROp("packed-switch"),Op("return-void")],tries=[])
    with self.assertRaises(Deny):inspect_pair(one(ROp("const/4")),b,D,D)
 def test_36_original_method_set_adversarial_denied(self):
    a={START:one(ROp("const/4"))}
    b={START:one(ROp("const/16",4)),OTHER:one(ROp("const/4"))}
    with self.assertRaises(Deny):audit(a,b,D,D)
if __name__=="__main__":unittest.main()
