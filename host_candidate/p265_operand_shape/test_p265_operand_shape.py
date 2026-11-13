#!/usr/bin/env python3
"""P265 28 fail-closed, privacy-preserving operand-shape diagnosis fixtures."""
import contextlib,enum,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
              "host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation",
              "host_candidate/p253_cfg_ordinal",
              "host_candidate/p255_branch_separation",
              "host_candidate/p257_opcode_family",
              "host_candidate/p259_all_operands",
              "host_candidate/p261_all_method_census",
              "host_candidate/p263_operand_correlation"]
from p246_exception_semantics import Deny
from p249_dual_diff import START,HELPER
from test_p253_cfg_ordinal import OTHER,Op,D
from test_p259_all_operands import op,method,before,after
from p265_operand_shape import CAUSES,raw_signature,shape_cause,report,emit

def base():
    return method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
def different_arity():
    return method(op("const/4",2,((0,0),)),op("return-void",2,()))
def different_kind():
    return method(op("const/4",2,((0,0),(0,7))),op("return-void",2,()))
def src(name="const/4",width=2,raw=((0,0),(1,7))):
    return (0,name,width,op(name,width,raw))
def scan(a=None,b=None):
    return report({START:base() if a is None else a},
                  {START:different_arity() if b is None else b},D,D)
class Tag(enum.IntEnum):
    REGISTER=0
    LITERAL=1
class Tests(unittest.TestCase):
 def test_01_normalized_arity(self):
    self.assertEqual(shape_cause(src(),src(raw=((0,0),))),"NORMALIZED_ITEM_COUNT")
 def test_02_normalized_tag(self):
    self.assertEqual(shape_cause(src(),src(raw=((0,0),(0,7)))),"NORMALIZED_ITEM_KIND")
 def test_03_normalized_value_difference_kept_unattested(self):
    self.assertEqual(shape_cause(src(),src(raw=((0,0),(1,8)))),"NORMALIZED_VALUES_CHANGED")
 def test_04_enum_tag_is_supported(self):
    a=src(raw=((Tag.REGISTER,0),(Tag.LITERAL,7)))
    self.assertEqual(shape_cause(a,src()),"NORMALIZED_VALUES_CHANGED")
 def test_05_raw_item_count(self):
    a=src(raw=((2,3),))
    b=src(raw=((2,3),(2,4)))
    self.assertEqual(shape_cause(a,b),"RAW_ITEM_COUNT")
 def test_06_raw_tag_diff(self):
    self.assertEqual(shape_cause(src(raw=((2,3),)),src(raw=((4,3),))),"RAW_TAG_ORDER")
 def test_07_raw_item_arity(self):
    a=src(raw=((260,3,"S"),))
    b=src(raw=((260,3,"S","EXTRA"),))
    self.assertEqual(shape_cause(a,b),"RAW_ITEM_ARITY")
 def test_08_same_raw_layout_but_unsupported(self):
    self.assertEqual(shape_cause(src(raw=((2,3),)),src(raw=((2,4),))),
                     "RAW_LAYOUT_SAME_UNATTESTED")
 def test_09_both_missing_api(self):
    a=(0,"const/4",2,Op("const/4"))
    self.assertEqual(shape_cause(a,a),"BOTH_SIDES_UNDECODABLE")
 def test_10_one_missing_api(self):
    a=(0,"const/4",2,Op("const/4"))
    self.assertEqual(shape_cause(a,src()),"ONE_SIDE_UNDECODABLE")
 def test_11_unknown_operand_tag_not_value(self):
    self.assertEqual(raw_signature(op(raw=((2,9999),))),((2,2),))
 def test_12_missing_operands_api_unknown(self):
    self.assertIsNone(raw_signature(Op("nop")))
 def test_13_malformed_raw_not_counted_as_verified(self):
    self.assertIsNone(raw_signature(op(raw=((2,),))))
 def test_14_nonlist_raw_not_verified(self):
    class Weird(Op):
        def get_operands(self):return object()
    self.assertIsNone(raw_signature(Weird("nop")))
 def test_15_raw_decoder_exception_sanitized(self):
    class Broken(Op):
        def get_operands(self):raise RuntimeError("SECRET-DO-NOT-PRINT")
    self.assertIsNone(raw_signature(Broken("nop")))
 def test_16_actual_classified_arity(self):
    q=scan()
    self.assertEqual((q["shape_methods"],q["causes"]["NORMALIZED_ITEM_COUNT"]),(1,1))
 def test_17_actual_classified_tag(self):
    q=scan(b=different_kind())
    self.assertEqual(q["causes"]["NORMALIZED_ITEM_KIND"],1)
 def test_18_opcode_encoding_pair_can_still_have_shape_mismatch(self):
    a=method(op("const/4",2,((0,0),(1,7))),op("return-void",2,()))
    b=method(op("const/16",4,((0,0),)),op("return-void",2,()))
    self.assertEqual(report({START:a},{START:b},D,D)["causes"]["NORMALIZED_ITEM_COUNT"],1)
 def test_19_other_method_counted_not_silently_ignored(self):
    q=report({START:before(),OTHER:base()},
             {START:after(),OTHER:different_arity()},D,D)
    self.assertEqual(q["shape_methods"],1)
 def test_20_unknown_methods_remain_unknown(self):
    unknown=method(Op("move"),op("return-void",2,()))
    q=report({START:base(),OTHER:unknown},
             {START:different_arity(),OTHER:unknown},D,D)
    self.assertEqual((q["shape_methods"],q["unknown_methods"]),(1,1))
 def test_21_no_differences_report_zero(self):
    q=scan(base(),base())
    self.assertEqual((q["shape_methods"],sum(q["causes"].values())),(0,0))
 def test_22_unapproved_new_method_denied(self):
    with self.assertRaises(Deny):
        report({START:base()},{START:different_arity(),OTHER:base()},D,D)
 def test_23_only_pinned_helper_extra(self):
    q=report({START:base()},{START:different_arity(),HELPER:base()},D,D)
    self.assertEqual(q["shape_methods"],1)
 def test_24_public_output_only_fixed_categories(self):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(scan()),2)
    s=buf.getvalue()
    self.assertIn("P265_SHAPE_NORMALIZED_ITEM_COUNT=1",s)
    self.assertIn("P265_RELEASE=DENY",s)
    self.assertIn("P265_ALL_UNKNOWN_METHODS=NOT_ATTESTED",s)
    self.assertNotIn(START[0],s)
 def test_25_public_schema_spoof_denied(self):
    q=scan();q["causes"]["METHOD_PRIVATE"]=1
    with self.assertRaises(Deny):emit(q)
 def test_26_public_count_spoof_denied(self):
    q=scan();q["causes"]["NORMALIZED_ITEM_COUNT"]=2
    with self.assertRaises(Deny):emit(q)
 def test_27_public_unknown_negative_denied(self):
    q=scan();q["unknown_methods"]=-1
    with self.assertRaises(Deny):emit(q)
 def test_28_enum_fixed_and_canonical(self):
    self.assertEqual(len(set(CAUSES)),len(CAUSES))
    self.assertTrue({"NORMALIZED_ITEM_COUNT","NORMALIZED_ITEM_KIND",
                    "RAW_ITEM_COUNT","RAW_TAG_ORDER","RAW_ITEM_ARITY"}.issubset(CAUSES))
if __name__=="__main__":unittest.main()
