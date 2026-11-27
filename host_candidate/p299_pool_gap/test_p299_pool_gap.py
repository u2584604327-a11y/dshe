#!/usr/bin/env python3
"""P299 adverse synthetic root-cause isolation; no private references logged."""
import contextlib,io,sys,unittest
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
 "host_candidate/p297_raw_invoke_pool",
 "host_candidate/p298_other_pool_refs",
]
from test_p295_raw_unknowns import Ins,Method
from test_p298_other_pool_refs import Pool,op,method,same
from p246_exception_semantics import Deny
import p299_pool_gap as p
def failure(a,b=None,da=None,db=None):
 return p.classify(a,b or a,da or Pool(),db or Pool())
class Cases(unittest.TestCase):
 def test_01_no_reference_no_missing(self):
  self.assertIsNone(failure(method()))
 def test_02_valid_string_no_missing(self):
  self.assertEqual(p.defects(same(0x1a),Pool()),frozenset())
 def test_03_valid_type_no_missing(self):
  self.assertEqual(p.defects(same(0x1c),Pool()),frozenset())
 def test_04_valid_field_no_missing(self):
  self.assertEqual(p.defects(same(0x52),Pool()),frozenset())
 def test_05_missing_base_string_index(self):
  self.assertEqual(failure(same(0x1a,99),same(0x1a),
                           Pool(),Pool()),("STRING_LOOKUP_FAILED","BASE_ONLY"))
 def test_06_missing_candidate_string_index(self):
  self.assertEqual(failure(same(0x1a),same(0x1a,99),
                           Pool(),Pool()),("STRING_LOOKUP_FAILED","CANDIDATE_ONLY"))
 def test_07_missing_both_string_index(self):
  self.assertEqual(failure(same(0x1a,99),same(0x1a,99)),
                           ("STRING_LOOKUP_FAILED","BOTH"))
 def test_08_invalid_string_non_string(self):
  d=Pool(strings={1:None})
  self.assertEqual(failure(same(0x1a),da=d),("STRING_VALUE_INVALID","BASE_ONLY"))
 def test_09_string_oversize(self):
  d=Pool(strings={1:"x"*8200})
  self.assertEqual(failure(same(0x1a),da=d),("STRING_VALUE_INVALID","BASE_ONLY"))
 def test_10_missing_type_lookup(self):
  self.assertEqual(failure(same(0x1c,99),same(0x1c)),("TYPE_LOOKUP_FAILED","BASE_ONLY"))
 def test_11_invalid_type_return(self):
  d=Pool(types={1:None})
  self.assertEqual(failure(same(0x1c),da=d),("TYPE_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_12_invalid_type_internal_space(self):
  d=Pool(types={1:"Labc/Bad Class;"})
  self.assertEqual(failure(same(0x1c),da=d),("TYPE_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_13_invalid_type_array_void(self):
  d=Pool(types={1:"[V"})
  self.assertEqual(failure(same(0x1c),da=d),("TYPE_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_14_missing_field_lookup(self):
  self.assertEqual(failure(same(0x52,99),same(0x52)),("FIELD_LOOKUP_FAILED","BASE_ONLY"))
 def test_15_invalid_field_tuple_length(self):
  d=Pool(fields={1:("Labc/Foo;","I")})
  self.assertEqual(failure(same(0x52),da=d),("FIELD_TUPLE_INVALID","BASE_ONLY"))
 def test_16_invalid_field_tuple_type(self):
  d=Pool(fields={1:"bad"})
  self.assertEqual(failure(same(0x52),da=d),("FIELD_TUPLE_INVALID","BASE_ONLY"))
 def test_17_invalid_field_owner(self):
  d=Pool(fields={1:("bad","I","field")})
  self.assertEqual(failure(same(0x52),da=d),("FIELD_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_18_invalid_field_descriptor(self):
  d=Pool(fields={1:("Labc/Foo;","V","field")})
  self.assertEqual(failure(same(0x52),da=d),("FIELD_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_19_invalid_field_name(self):
  d=Pool(fields={1:("Labc/Foo;","I","bad field")})
  self.assertEqual(failure(same(0x52),da=d),("FIELD_DESCRIPTOR_INVALID","BASE_ONLY"))
 def test_20_candidate_field_mismatch_return(self):
  d=Pool(fields={1:("Labc/Foo;","I","bad field")})
  self.assertEqual(failure(same(0x52),db=d),("FIELD_DESCRIPTOR_INVALID","CANDIDATE_ONLY"))
 def test_21_duplicate_same_cause_stays_one(self):
  d=Pool(strings={1:None})
  x=method(op(0x1a),op(0x1a))
  self.assertEqual(failure(x,da=d),("STRING_VALUE_INVALID","BASE_ONLY"))
 def test_22_multiple_missing_kinds_preserved(self):
  d=Pool(strings={1:None},types={1:None})
  x=method(op(0x1a),op(0x1c))
  self.assertEqual(failure(x,da=d),("MULTIPLE_OR_UNVERIFIED","BASE_ONLY"))
 def test_23_multiple_kinds_two_sides(self):
  a=Pool(strings={1:None});b=Pool(types={1:None})
  x=method(op(0x1a),op(0x1c))
  self.assertEqual(failure(x,da=a,db=b),("MULTIPLE_OR_UNVERIFIED","BOTH"))
 def test_24_valid_but_changed_target_not_misclassified_missing(self):
  self.assertIsNone(failure(same(0x1a,1),same(0x1a,3)))
 def test_25_invalid_instruction_returns_raw_defect(self):
  x=same(0x1a);x.rows[0]=(2,x.rows[0][1])
  self.assertEqual(p.defects(x,Pool()),frozenset({"RAW_OR_LAYOUT_UNVERIFIED"}))
 def test_26_missing_pool_accessor(self):
  self.assertEqual(p.reason_for_pool(object(),"STRING",1),"STRING_LOOKUP_FAILED")
 def test_27_missing_type_accessor(self):
  self.assertEqual(p.reason_for_pool(object(),"TYPE",1),"TYPE_LOOKUP_FAILED")
 def test_28_missing_field_accessor(self):
  self.assertEqual(p.reason_for_pool(object(),"FIELD",1),"FIELD_LOOKUP_FAILED")
 def test_29_unknown_kind_is_unverified(self):
  self.assertEqual(p.reason_for_pool(object(),"NONE",1),"MULTIPLE_OR_UNVERIFIED")
 def test_30_emit_one_diagnostic_no_release(self):
  a={k:0 for k in p.KINDS};b={k:0 for k in p.SIDES}
  a["FIELD_DESCRIPTOR_INVALID"]=1;b["CANDIDATE_ONLY"]=1
  result={"unknown":492,"unavailable":1,"causes":a,"sides":b}
  out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertEqual(p.emit(result),2)
  s=out.getvalue()
  self.assertIn("P299_RELEASE=DENY",s)
  self.assertIn("P299_OTHER_POOL_UNAVAILABLE=1",s)
  self.assertNotIn("Labc/Foo;",s)
 def test_31_forged_total_denied(self):
  x={"unknown":492,"unavailable":1,"causes":{k:0 for k in p.KINDS},
     "sides":{k:0 for k in p.SIDES}}
  with self.assertRaises(Deny):p.emit(x)
 def test_32_forged_extra_category_denied(self):
  x={"unknown":0,"unavailable":0,"causes":{k:0 for k in p.KINDS},
     "sides":{k:0 for k in p.SIDES}}
  x["causes"]["ALLOW"]=0
  with self.assertRaises(Deny):p.emit(x)
 def test_33_negative_count_denied(self):
  x={"unknown":0,"unavailable":-1,"causes":{k:0 for k in p.KINDS},
     "sides":{k:0 for k in p.SIDES}}
  with self.assertRaises(Deny):p.emit(x)
 def test_34_source_only_no_real_claim(self):
  old=sys.argv;sys.argv=["p299"]
  try:
   out=io.StringIO()
   with contextlib.redirect_stdout(out):self.assertEqual(p.main(),0)
   self.assertIn("P299_REAL_ROOT_CAUSE=NOT_ATTESTED",out.getvalue())
   self.assertIn("P299_RELEASE=DENY",out.getvalue())
  finally:sys.argv=old

if __name__=="__main__":unittest.main()
