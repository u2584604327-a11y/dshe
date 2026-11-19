#!/usr/bin/env python3
"""P275 isolated source-only adversarial classification and pool-byte fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p275_encoding_width","host_candidate/p257_opcode_family",
             "host_candidate/p249_dual_diff","host_candidate/p246_exception_semantics"]
from p246_exception_semantics import Deny
from p275_encoding_width import (
 transition,string_index,pool_string,compare_string_refs,emit,main,
 TRANSITIONS,WIDTHS,STRING_REFS,JUMBO_INDEX,METHOD_FIELDS
)
class Ins:
 def __init__(self,raw):self.raw=raw
 def get_raw(self):return self.raw
class Explode:
 def get_raw(self):raise RuntimeError("PRIVATE_SHOULD_NOT_LEAK")
class Dex:
 def __init__(self,strings=None):self.strings=strings or {}
 def get_cm_string(self,index):
    return self.strings[index]
def rec(name,width,ins):
 return (0,name,width,ins)
def string_row(idx=50,reg=2,jumbo=False,raw=None):
 name="const-string/jumbo" if jumbo else "const-string"
 w=6 if jumbo else 4
 if raw is None:
    raw=bytes([0x1b if jumbo else 0x1a,reg])+idx.to_bytes(4 if jumbo else 2,"little")
 return rec(name,w,Ins(raw))
def stringcheck(a=None,b=None,da=None,db=None):
 a=string_row() if a is None else a
 b=string_row(80000,jumbo=True) if b is None else b
 da=Dex({50:"SAME_PRIVATE_CONTENT"}) if da is None else da
 db=Dex({80000:"SAME_PRIVATE_CONTENT"}) if db is None else db
 return compare_string_refs(a,b,da,db)
def baseline():
 m={key:0 for key in METHOD_FIELDS}
 m["ORIGINAL_CODE_METHODS"]=52014
 m["CODE_SIZE_CHANGED"]=7
 m["SUPPORTED_ENCODING_METHODS"]=8
 m["SIZE_CHANGED_AND_ENCODING_METHODS"]=7
 m["RAW_EXCEPTION_CHANGED"]=3
 a={key:0 for key in TRANSITIONS};a["STRING_TO_JUMBO"]=7
 a["INVOKE_TO_RANGE"]=1
 w={key:0 for key in WIDTHS};w["POSITIVE"]=7;w["ZERO"]=1
 s={key:0 for key in STRING_REFS};s["SAME_STRING_SAME_REGISTER"]=7
 s["NOT_APPLICABLE"]=1
 j={key:0 for key in JUMBO_INDEX};j["JUMBO_REQUIRES_32BIT"]=7
 j["NOT_APPLICABLE"]=1
 return dict(methods=m,transitions=a,widths=w,strings=s,jumbo=j,
             code_gate="DENY",exception_gate="DENY")
class Tests(unittest.TestCase):
 def test_01_const_string_promotion(self):
    self.assertEqual(transition("const-string","const-string/jumbo",4,6),
                     ("STRING_TO_JUMBO","POSITIVE"))
 def test_02_const_string_demotion(self):
    self.assertEqual(transition("const-string/jumbo","const-string",6,4),
                     ("JUMBO_TO_STRING","NEGATIVE"))
 def test_03_const_string_invalid_size(self):
    self.assertEqual(transition("const-string","const-string/jumbo",6,6)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_04_goto_widen(self):
    self.assertEqual(transition("goto","goto/32",2,6),
                     ("GOTO_WIDEN","POSITIVE"))
 def test_05_goto_narrow(self):
    self.assertEqual(transition("goto/32","goto/16",6,4),
                     ("GOTO_NARROW","NEGATIVE"))
 def test_06_goto_same_width_impossible(self):
    self.assertEqual(transition("goto","goto/16",4,4)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_07_move_widen(self):
    self.assertEqual(transition("move","move/from16",2,4)[0],"MOVE_WIDEN")
 def test_08_move_narrow(self):
    self.assertEqual(transition("move-object/16","move-object",6,2)[0],
                     "MOVE_NARROW")
 def test_09_move_wide_valid(self):
    self.assertEqual(transition("move-wide","move-wide/16",2,6)[0],
                     "MOVE_WIDEN")
 def test_10_move_encoding_wrong_width(self):
    self.assertEqual(transition("move","move/16",2,4)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_11_invoke_to_range_size_same(self):
    self.assertEqual(transition("invoke-static","invoke-static/range",6,6),
                     ("INVOKE_TO_RANGE","ZERO"))
 def test_12_invoke_from_range(self):
    self.assertEqual(transition("invoke-virtual/range","invoke-virtual",6,6)[0],
                     "INVOKE_FROM_RANGE")
 def test_13_invoke_wrong_width(self):
    self.assertEqual(transition("invoke-static","invoke-static/range",4,6)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_14_const_widen(self):
    self.assertEqual(transition("const/4","const",2,6)[0],"CONST_WIDEN")
 def test_15_const_narrow(self):
    self.assertEqual(transition("const","const/16",6,4)[0],"CONST_NARROW")
 def test_16_const_wide_widen(self):
    self.assertEqual(transition("const-wide/16","const-wide",4,10)[0],
                     "CONST_WIDE_WIDEN")
 def test_17_const_wide_narrow(self):
    self.assertEqual(transition("const-wide","const-wide/32",10,6)[0],
                     "CONST_WIDE_NARROW")
 def test_18_nonfamily_opcode_changed(self):
    self.assertEqual(transition("return-void","move",2,2)[0],
                     "OPERATION_KIND_CHANGED")
 def test_19_input_bool_width_invalid(self):
    self.assertEqual(transition("move","move/16",True,6)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_20_identical_opcode_not_transition(self):
    self.assertEqual(transition("move","move",2,2)[0],
                     "INVALID_WIDTH_OR_OPCODE")
 def test_21_21c_index_parse(self):
    self.assertEqual(string_index(string_row(65535,4)[3],"const-string"),
                     (4,65535))
 def test_22_31c_index_parse(self):
    self.assertEqual(string_index(string_row(65536,3,True)[3],
                                  "const-string/jumbo"),(3,65536))
 def test_23_wrong_opcode_raw_unreadable(self):
    self.assertIsNone(string_index(Ins(b"\\x1b\\x02\\x00\\x00"),
                                   "const-string"))
 def test_24_truncated_jumbo_unreadable(self):
    self.assertIsNone(string_index(Ins(b"abc"),"const-string/jumbo"))
 def test_25_raw_exception_hidden(self):
    self.assertIsNone(string_index(Explode(),"const-string"))
 def test_26_string_pool_same_ref(self):
    self.assertEqual(stringcheck(),
                     ("SAME_STRING_SAME_REGISTER","JUMBO_REQUIRES_32BIT"))
 def test_27_string_pool_same_diff_register(self):
    self.assertEqual(stringcheck(b=string_row(80000,5,True))[0],
                     "SAME_STRING_REGISTER_DIFFER")
 def test_28_string_pool_different_content(self):
    self.assertEqual(stringcheck(db=Dex({80000:"OTHER"}))[0],
                     "DIFFERENT_STRING")
 def test_29_string_pool_unavailable(self):
    self.assertEqual(stringcheck(db=Dex({}))[0],
                     "POOL_REFERENCE_UNREADABLE")
 def test_30_jumbo_index_fits_16bit(self):
    a=string_row(50);b=string_row(65535,jumbo=True)
    self.assertEqual(stringcheck(a,b,Dex({50:"A"}),Dex({65535:"A"}))[1],
                     "JUMBO_FITS_16BIT")
 def test_31_non_string_not_applicable(self):
    self.assertEqual(stringcheck(a=rec("move",2,Ins(b"")),b=rec("move/16",6,Ins(b""))),
                     ("NOT_APPLICABLE","NOT_APPLICABLE"))
 def test_32_pool_type_invalid(self):
    self.assertIsNone(pool_string(Dex({3:b"BAD"}),3))
 def test_33_pool_index_negative(self):
    self.assertIsNone(pool_string(Dex(),-1))
 def test_34_private_output_exact_schema_deny(self):
    output=io.StringIO()
    with contextlib.redirect_stdout(output):self.assertEqual(emit(baseline()),2)
    s=output.getvalue()
    self.assertIn("P275_METHOD_CODE_SIZE_CHANGED=7",s)
    self.assertIn("P275_RELEASE=DENY",s)
    self.assertNotIn("SAME_PRIVATE_CONTENT",s)
 def test_35_spoofed_schema_fails_closed(self):
    q=baseline();q["transitions"]["BY_PASS"]=1
    with self.assertRaises(Deny):emit(q)
 def test_36_count_mismatch_fails_closed(self):
    q=baseline();q["widths"]["ZERO"]=0
    with self.assertRaises(Deny):emit(q)
 def test_37_missing_original_deny_fails(self):
    q=baseline();q["exception_gate"]="PARITY"
    with self.assertRaises(Deny):emit(q)
 def test_38_unaccounted_size_methods_fail(self):
    q=baseline();q["methods"]["SIZE_CHANGED_AND_ENCODING_METHODS"]=6
    with self.assertRaises(Deny):emit(q)
 def test_39_source_only_does_not_attest_real(self):
    old=sys.argv;sys.argv=["p275"]
    try:
     out=io.StringIO()
     with contextlib.redirect_stdout(out):self.assertEqual(main(),0)
     self.assertIn("P275_REAL_ENCODING_WIDTH_CENSUS=NOT_ATTESTED",out.getvalue())
     self.assertIn("P275_RELEASE=DENY",out.getvalue())
    finally:sys.argv=old
if __name__=="__main__":
 unittest.main()
