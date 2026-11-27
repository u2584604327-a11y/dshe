#!/usr/bin/env python3
"""P298 independent adverse original DEX field/type/string pool fixtures."""
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
]
from test_p295_raw_unknowns import Ins,Method
from p246_exception_semantics import Deny
import p298_other_pool_refs as p298
class Pool:
 def __init__(self,strings=None,types=None,fields=None):
  self.strings={1:"ALPHA",2:"ALPHA",3:"BETA",65537:"ALPHA"} if strings is None else strings
  self.types={1:"Labc/Foo;",2:"Labc/Foo;",3:"[Ljava/lang/Object;",4:"I"} if types is None else types
  self.fields={1:("Labc/Foo;","I","field"),2:("Labc/Foo;","I","field"),
    3:("Labc/Foo;","Ljava/lang/Object;","field")} if fields is None else fields
 def get_cm_string(self,i):return self.strings[i]
 def get_cm_type(self,i):return self.types[i]
 def get_cm_field(self,i):return self.fields[i]
def op(code,index=1,*,width=None,body=None):
 spec=p298.REF_SPEC.get(code)
 w=width or (spec[1] if spec else 6)
 idxwidth=spec[2] if spec else 2
 if body is None:
  body=bytes((code,0))+int(index).to_bytes(idxwidth,"little")+bytes(w-2-idxwidth)
 return Ins("raw-op",body)
def method(*ops):
 return Method(*(ops or (Ins("return-void",b"\x0e\x00"),)))
def same(code,index=1):
 return method(op(code,index))
P="MATCHING_OTHER_REFERENCE_TARGETS_CANDIDATE"
D="DIFFERENT_OTHER_REFERENCE_TARGET"
U="OTHER_REFERENCE_POOL_UNAVAILABLE"
X="UNSUPPORTED_REFERENCE_ENCODING"
N="NO_OTHER_POOL_REFERENCE_OBSERVED"
L="INSTRUCTION_LAYOUT_UNVERIFIED"
class Tests(unittest.TestCase):
 def setUp(self):
  self.a=Pool();self.b=Pool()
 def test_01_decode_short_string_index(self):
  self.assertEqual(p298.references(same(0x1a),self.a),((0,0x1a,"STRING","ALPHA"),))
 def test_02_jumbo_32bit_index(self):
  self.assertEqual(p298.references(same(0x1b,65537),self.a),((0,0x1b,"STRING","ALPHA"),))
 def test_03_const_class_type(self):
  self.assertEqual(p298.references(same(0x1c),self.a),((0,0x1c,"TYPE","Labc/Foo;"),))
 def test_04_check_cast_type(self):
  self.assertEqual(p298.category(same(0x1f),same(0x1f),self.a,self.b),P)
 def test_05_instanceof_type(self):
  self.assertEqual(p298.category(same(0x20),same(0x20),self.a,self.b),P)
 def test_06_new_instance_type(self):
  self.assertEqual(p298.category(same(0x22),same(0x22),self.a,self.b),P)
 def test_07_new_array_type(self):
  self.assertEqual(p298.category(same(0x23),same(0x23),self.a,self.b),P)
 def test_08_filled_new_array_35c(self):
  self.assertEqual(p298.category(same(0x24),same(0x24),self.a,self.b),P)
 def test_09_filled_new_array_range(self):
  self.assertEqual(p298.category(same(0x25),same(0x25),self.a,self.b),P)
 def test_10_iget_field(self):
  self.assertEqual(p298.references(same(0x52),self.a)[0][-1],("Labc/Foo;","I","field"))
 def test_11_iput_field(self):
  self.assertEqual(p298.category(same(0x59),same(0x59),self.a,self.b),P)
 def test_12_sget_field(self):
  self.assertEqual(p298.category(same(0x60),same(0x60),self.a,self.b),P)
 def test_13_sput_field(self):
  self.assertEqual(p298.category(same(0x6d),same(0x6d),self.a,self.b),P)
 def test_14_multiple_string_type_field_refs(self):
  m=method(op(0x1a),op(0x1c),op(0x52))
  self.assertEqual(tuple(x[2] for x in p298.references(m,self.a)),("STRING","TYPE","FIELD"))
 def test_15_different_string_index_same_resolved(self):
  self.assertEqual(p298.category(same(0x1a,1),same(0x1a,2),self.a,self.b),P)
 def test_16_same_string_index_different_pool(self):
  b=Pool(strings={1:"BETA"})
  self.assertEqual(p298.category(same(0x1a),same(0x1a),self.a,b),D)
 def test_17_string_value_changed(self):
  self.assertEqual(p298.category(same(0x1a,1),same(0x1a,3),self.a,self.b),D)
 def test_18_type_value_changed(self):
  self.assertEqual(p298.category(same(0x1c,1),same(0x1c,3),self.a,self.b),D)
 def test_19_field_descriptor_changed(self):
  self.assertEqual(p298.category(same(0x52,1),same(0x52,3),self.a,self.b),D)
 def test_20_field_index_different_same_resolved(self):
  self.assertEqual(p298.category(same(0x52,1),same(0x52,2),self.a,self.b),P)
 def test_21_string_pool_index_missing(self):
  self.assertEqual(p298.category(same(0x1a,999),same(0x1a,1),self.a,self.b),U)
 def test_22_type_pool_missing(self):
  self.assertEqual(p298.category(same(0x1c,999),same(0x1c,1),self.a,self.b),U)
 def test_23_field_pool_missing(self):
  self.assertEqual(p298.category(same(0x52,999),same(0x52,1),self.a,self.b),U)
 def test_24_invalid_field_tuple(self):
  bad=Pool(fields={1:("Labc/Foo;", "I")})
  self.assertIsNone(p298.references(same(0x52),bad))
 def test_25_malformed_field_class(self):
  bad=Pool(fields={1:("bad", "I","f")})
  self.assertEqual(p298.category(same(0x52),same(0x52),self.a,bad),U)
 def test_26_malformed_field_name(self):
  bad=Pool(fields={1:("Labc/Foo;","I","f x")})
  self.assertEqual(p298.category(same(0x52),same(0x52),self.a,bad),U)
 def test_27_invalid_field_void_type(self):
  bad=Pool(fields={1:("Labc/Foo;","V","f")})
  self.assertEqual(p298.category(same(0x52),same(0x52),self.a,bad),U)
 def test_28_invalid_array_void_type(self):
  self.assertFalse(p298.valid_type("[V"))
 def test_29_array_of_object_valid(self):
  self.assertTrue(p298.valid_type("[[Ljava/lang/Object;"))
 def test_30_type_internal_space_rejected(self):
  self.assertFalse(p298.valid_type("Labc/Bad Field;"))
 def test_31_invalid_string_pool_return(self):
  bad=Pool(strings={1:None})
  self.assertEqual(p298.category(same(0x1a),same(0x1a),self.a,bad),U)
 def test_32_unsupported_const_method_handle(self):
  x=method(Ins("const-method-handle",b"\xfe\x00\x01\x00"))
  self.assertEqual(p298.category(x,x,self.a,self.b),X)
 def test_33_unsupported_invoke_custom(self):
  x=method(Ins("invoke-custom",b"\xfc\x10\x01\x00\x00\x00"))
  self.assertEqual(p298.category(x,x,self.a,self.b),X)
 def test_34_unsupported_reserved_opcode(self):
  x=method(Ins("unknown",b"\xe3\x00"))
  self.assertEqual(p298.category(x,x,self.a,self.b),X)
 def test_35_invoke_only_does_not_attest_other_refs(self):
  x=method(Ins("invoke-static",b"\x71\x10\x01\x00\x00\x00"))
  self.assertEqual(p298.category(x,x,self.a,self.b),N)
 def test_36_return_only_has_no_other_refs(self):
  self.assertEqual(p298.category(method(),method(),self.a,self.b),N)
 def test_37_wrong_length_for_const_string(self):
  x=method(Ins("const-string",b"\x1a\x00\x01\x00\x00\x00"))
  self.assertEqual(p298.category(x,x,self.a,self.b),U)
 def test_38_instruction_coverage_gap(self):
  x=same(0x1a);x.rows[0]=(2,x.rows[0][1])
  self.assertEqual(p298.category(x,same(0x1a),self.a,self.b),L)
 def test_39_length_mismatch(self):
  self.assertEqual(p298.category(same(0x1a),same(0x1b,65537),self.a,self.b),L)
 def test_40_op_changed(self):
  self.assertEqual(p298.category(same(0x1c),same(0x1a),self.a,self.b),L)
 def test_41_one_side_more_references(self):
  a=method(op(0x1a),Ins("return-void",b"\x0e\x00"))
  b=method(op(0x1a),op(0x1a))
  self.assertEqual(p298.category(a,b,self.a,self.b),L)
 def test_42_missing_pool_method(self):
  self.assertEqual(p298.category(same(0x1a),same(0x1a),self.a,object()),U)
 def test_43_emit_stays_deny_and_sanitized(self):
  q={"count":1,"categories":{x:int(x==P) for x in p298.CATEGORIES}}
  out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertEqual(p298.emit(q),2)
  body=out.getvalue()
  self.assertIn("P298_RELEASE=DENY",body)
  self.assertIn("P298_SWITCH_PAYLOAD_REGISTERS_ART=NOT_ATTESTED",body)
  self.assertNotIn("ALPHA",body)
 def test_44_forged_counter_denied(self):
  q={"count":1,"categories":{x:0 for x in p298.CATEGORIES}}
  with self.assertRaises(Deny):p298.emit(q)
 def test_45_forged_schema_denied(self):
  q={"count":0,"categories":{x:0 for x in p298.CATEGORIES}}
  q["categories"]["BYPASS"]=1
  with self.assertRaises(Deny):p298.emit(q)
 def test_46_source_only_no_real_claim(self):
  old=sys.argv;sys.argv=["p298"]
  try:
   out=io.StringIO()
   with contextlib.redirect_stdout(out):self.assertEqual(p298.main(),0)
   self.assertIn("P298_REAL_OTHER_POOL_REFS=NOT_ATTESTED",out.getvalue())
  finally:sys.argv=old

if __name__=="__main__":unittest.main()
