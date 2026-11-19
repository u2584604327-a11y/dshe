#!/usr/bin/env python3
"""P263 26 synthetic all-method operand-difference/unknown-reason fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
             "host_candidate/p249_dual_diff",
             "host_candidate/p251_method_relation",
             "host_candidate/p253_cfg_ordinal",
             "host_candidate/p255_branch_separation",
             "host_candidate/p257_opcode_family",
             "host_candidate/p259_all_operands",
             "host_candidate/p261_all_method_census"]
from p246_exception_semantics import Deny
from p249_dual_diff import START,HELPER
from test_p253_cfg_ordinal import D,OTHER,Op
from test_p259_all_operands import op,method,before,after
from p263_operand_correlation import changed_kind,mismatch_types,diagnose,emit,FIELDS

def one(x=None,y=None):
    return diagnose({START:before() if x is None else x},
                    {START:after() if y is None else y},D,D)
def both(x=None,y=None):
    return diagnose({START:before(),OTHER:before()},
                    {START:after(),OTHER:before() if y is None else y},D,D)
def lit(value=9):
    return method(op("const/4",2,((0,0),(1,value))),
                  op("move",2,((0,1),(0,0))),
                  op("return-void",2,()))
def reg(value=2):
    return method(op("const/4",2,((0,value),(1,7))),
                  op("move",2,((0,1),(0,0))),
                  op("return-void",2,()))
def symbol(value="NEW"):
    return method(op("const-string",4,((0,0),(260,3,value))),
                  op("return-void",2,()))
class Tests(unittest.TestCase):
 def test_01_no_structured_divergence(self):
    self.assertEqual(one()["divergence"],0)
 def test_02_first_size_candidate_matching_not_false_divergence(self):
    self.assertEqual(one()["counts"]["DIVERGENT_SIZE_CHANGED"],0)
 def test_03_same_size_literal_divergence_caught(self):
    q=both(y=lit())
    self.assertEqual(q["counts"]["DIVERGENT_SIZE_STABLE"],1)
 def test_04_literal_category_caught(self):
    q=both(y=lit())
    self.assertEqual(q["counts"]["DIVERGENT_LITERAL"],1)
 def test_05_same_opcode_category_caught(self):
    q=both(y=lit())
    self.assertEqual(q["counts"]["DIVERGENT_OPCODE_UNCHANGED"],1)
 def test_06_register_category_caught(self):
    self.assertEqual(both(y=reg())["counts"]["DIVERGENT_REGISTER"],1)
 def test_07_resolved_reference_category(self):
    self.assertEqual(one(symbol("OLD"),symbol("NEW"))["counts"]["DIVERGENT_RESOLVED_REFERENCE"],1)
 def test_08_reference_index_remap_same_symbol(self):
    a=method(op("const-string",4,((0,0),(260,3,"MATCH"))),op("return-void",2,()))
    b=method(op("const-string/jumbo",6,((0,0),(260,30,"MATCH"))),op("return-void",2,()))
    self.assertEqual(one(a,b)["divergence"],0)
 def test_09_encoding_opcode_and_changed_literal(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("const/16",4,((0,0),(1,8))),op("return-void",2,()))
    q=one(a,b)
    self.assertEqual((q["counts"]["DIVERGENT_OPCODE_ENCODING"],
                      q["counts"]["DIVERGENT_LITERAL"]), (1,1))
 def test_10_size_changed_operand_divergence(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("const/16",4,((0,0),(1,8))),op("return-void",2,()))
    self.assertEqual(one(a,b)["counts"]["DIVERGENT_SIZE_CHANGED"],1)
 def test_11_operation_kind_changed_classified(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("move",2,((0,0),(0,1))),op("return-void",2,()))
    q=one(a,b)
    self.assertEqual((q["counts"]["DIVERGENT_OPCODE_KIND"],
                      q["counts"]["DIVERGENT_OPERAND_SHAPE"]),(1,1))
 def test_12_operand_arity_diff(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("const/4",2,((0,0),)),op("return-void",2,()))
    self.assertEqual(one(a,b)["counts"]["DIVERGENT_OPERAND_SHAPE"],1)
 def test_13_multi_category_inside_one_instruction(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("const/4",2,((0,1),(1,9))),op("return-void",2,()))
    self.assertEqual(one(a,b)["counts"]["DIVERGENT_MULTIPLE_TYPES"],1)
 def test_14_payload_not_attested(self):
    p=method(op("packed-switch",2,((3,2),)),op("return-void",2,()))
    q=one(p,p)
    self.assertEqual((q["unknown"],q["counts"]["UNKNOWN_PAYLOAD"]),(1,1))
 def test_15_fill_array_not_attested(self):
    p=method(op("fill-array-data",2,((3,2),)),op("return-void",2,()))
    self.assertEqual(one(p,p)["counts"]["UNKNOWN_PAYLOAD"],1)
 def test_16_missing_api_not_attested(self):
    a=method(Op("move"),op("return-void",2,()))
    self.assertEqual(one(a,a)["counts"]["UNKNOWN_OPERAND_FORMAT"],1)
 def test_17_unresolved_reference_not_attested(self):
    a=method(op("const-string",4,((0,0),(260,3))),op("return-void",2,()))
    self.assertEqual(one(a,a)["counts"]["UNKNOWN_OPERAND_FORMAT"],1)
 def test_18_instruction_count_unattested(self):
    b=method(op("const/16",4),op("return-void",2,()))
    self.assertEqual(one(before(),b)["counts"]["UNKNOWN_INSTRUCTION_COUNT"],1)
 def test_19_extra_method_not_allowed(self):
    with self.assertRaises(Deny):
        diagnose({START:before()},{START:after(),OTHER:before()},D,D)
 def test_20_missing_method_not_allowed(self):
    with self.assertRaises(Deny):
        diagnose({START:before(),OTHER:before()},{START:after()},D,D)
 def test_21_original_helper_only_allowed(self):
    q=diagnose({START:before()},{START:after(),HELPER:before()},D,D)
    self.assertEqual(q["original_code_methods"],1)
 def test_22_output_cannot_leak_private_method(self):
    q=both(y=lit())
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(q),2)
    s=buf.getvalue()
    self.assertNotIn(START[0],s)
    self.assertNotIn(OTHER[0],s)
    self.assertIn("P263_IDENTIT" ,s)
    self.assertIn("P263_RELEASE=DENY",s)
 def test_23_output_enum_does_not_trust_new_fields(self):
    q=one();q["counts"]["PRIVATE_OPERAND"]=1
    with self.assertRaises(Deny):emit(q)
 def test_24_output_invariant_unknown_enforced(self):
    q=one();q["counts"]["UNKNOWN_OTHER"]=1
    with self.assertRaises(Deny):emit(q)
 def test_25_explicit_empty_missing_categories(self):
    q=one()
    self.assertEqual(set(q["counts"]),set(FIELDS))
 def test_26_false_release_even_no_mismatch(self):
    q=one()
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(q),2)
    self.assertIn("P263_COMPLETE_SEMANTIC_PARITY=NOT_ATTESTED",buf.getvalue())
if __name__=="__main__":unittest.main()
