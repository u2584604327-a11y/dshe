#!/usr/bin/env python3
"""P281: 37 private, fail-closed helper predicates / raw refs / typed catch tests."""
import contextlib
import io
import sys
import unittest
from unittest.mock import patch
sys.path[:0]=[
 "host_candidate/p281_helper_predicates",
 "host_candidate/p269_method_pool",
 "host_candidate/p267_invoke_words",
 "host_candidate/p249_dual_diff",
 "host_candidate/p246_exception_semantics",
]
import p281_helper_predicates as mod
from p246_exception_semantics import Deny

class Op:
 def __init__(self,name,out="",raw=b"",size=2):
    self.name,self.out,self.raw,self.size=name,out,raw,size
 def get_name(self):return self.name
 def get_output(self):return self.out
 def get_length(self):return self.size
 def get_raw(self):return self.raw

class Code:
 def __init__(self,tries=1,outs=2,regs=5):
    self.tries,self.outs,self.regs=tries,outs,regs
 def get_tries_size(self):return self.tries
 def get_outs_size(self):return self.outs
 def get_registers_size(self):return self.regs

class Method:
 def __init__(self,rows=None,tries=1,outs=2,regs=5):
    self.rows=rows if rows is not None else fresh_rows()
    self.code=Code(tries,outs,regs)
 def get_instructions_idx(self):return list(self.rows)
 def get_code(self):return self.code

class Dex:
 def __init__(self,refs=None):
    self.refs={1:(mod.GETTER[0],mod.GETTER[1],mod.GETTER[2:]),
               2:(mod.LOG[0],mod.LOG[1],mod.LOG[2:])} if refs is None else refs
 def get_cm_method(self,i):return self.refs[i]

def fresh_rows():
    return [
     (0,Op("iget-object","v0,v4",size=4)),
     (4,Op("invoke-static",mod.GETTER_OUTPUT,
           bytes((0x71,0x10,0x01,0x00,0x00,0x00)),size=6)),
     (10,Op("invoke-static",mod.LOG_OUTPUT,
            bytes((0x71,0x20,0x02,0x00,0x21,0x00)),size=6)),
     (16,Op("move-exception","v0",size=2)),
    ]

def replace(m,i,**updates):
    m.rows=list(m.rows)
    pc,op=m.rows[i]
    m.rows[i]=(pc,Op(updates.get("name",op.name),
        updates.get("output",op.out),updates.get("raw",op.raw),
        updates.get("size",op.size)))
    return m

def fake_decoded(kind="valid",target=8):
    if kind=="valid":
        return (9,((0,8,((("Ljava/lang/Throwable;",target),),None)),))
    if kind=="badtype":
        return (9,((0,8,((("Ljava/lang/Error;",target),),None)),))
    if kind=="catchall":
        return (9,((0,8,((),target)),))
    if kind=="extra":
        return (9,((0,8,((("Ljava/lang/Throwable;",target),("Ljava/lang/Error;",target)),None)),))
    return (9,())
def valid():
    return {"witness":"ONE_ONLY",
       "predicates":{x:"PASS" for x in mod.PREDICATES},
       "counts":{"IGET_OBJECT_COUNT":1,"INVOKE_STATIC_COUNT":2,
                 "INVOKE_STATIC_RANGE_COUNT":0,"TRY_COUNT":1},
       "pool":"BOTH_EXACT","handler":"ONE_TYPED_THROWABLE_MOVE_EXCEPTION"}

class Tests(unittest.TestCase):
 def test_01_five_good_predicates(self):
    self.assertEqual(mod.p245_checks(Method())["predicates"],
                     {x:True for x in mod.PREDICATES})
 def test_02_one_try(self):
    self.assertEqual(mod.p245_checks(Method())["counts"]["TRY_COUNT"],1)
 def test_03_iget_exactly_one(self):
    self.assertEqual(mod.p245_checks(Method())["counts"]["IGET_OBJECT_COUNT"],1)
 def test_04_invoke_static_exactly_two(self):
    self.assertEqual(mod.p245_checks(Method())["counts"]["INVOKE_STATIC_COUNT"],2)
 def test_05_getter_string_exact(self):
    self.assertTrue(mod.p245_checks(Method())["predicates"]["GETTER_OUTPUT_PRESENT"])
 def test_06_log_string_exact(self):
    self.assertTrue(mod.p245_checks(Method())["predicates"]["LOG_I_OUTPUT_PRESENT"])
 def test_07_none_method_unverified(self):
    self.assertIsNone(mod.p245_checks(None))
 def test_08_missing_code_unverified(self):
    m=Method();m.code=None
    self.assertIsNone(mod.p245_checks(m))
 def test_09_missing_output_unverified(self):
    m=Method();m.rows[1][1].out=None
    self.assertIsNone(mod.p245_checks(m))
 def test_10_gap_in_pc_unverified(self):
    m=Method();m.rows[1]=(6,m.rows[1][1])
    self.assertIsNone(mod.p245_checks(m))
 def test_11_odd_width_unverified(self):
    m=replace(Method(),0,size=3)
    self.assertIsNone(mod.p245_checks(m))
 def test_12_negative_pc_unverified(self):
    m=Method();m.rows[0]=(-1,m.rows[0][1])
    self.assertIsNone(mod.p245_checks(m))
 def test_13_unbounded_output_unverified(self):
    m=replace(Method(),1,output="SECRET"*2000)
    self.assertIsNone(mod.p245_checks(m))
 def test_14_try_zero_false(self):
    self.assertFalse(mod.p245_checks(Method(tries=0))["predicates"]["ONE_TRY"])
 def test_15_try_two_false(self):
    self.assertFalse(mod.p245_checks(Method(tries=2))["predicates"]["ONE_TRY"])
 def test_16_iget_zero_false(self):
    m=replace(Method(),0,name="iget")
    self.assertFalse(mod.p245_checks(m)["predicates"]["ONE_IGET_OBJECT"])
 def test_17_iget_two_false(self):
    m=replace(Method(),3,name="iget-object")
    self.assertFalse(mod.p245_checks(m)["predicates"]["ONE_IGET_OBJECT"])
 def test_18_static_one_false(self):
    m=replace(Method(),1,name="invoke-direct")
    self.assertFalse(mod.p245_checks(m)["predicates"]["TWO_INVOKE_STATIC"])
 def test_19_static_three_false(self):
    m=replace(Method(),3,name="invoke-static")
    self.assertFalse(mod.p245_checks(m)["predicates"]["TWO_INVOKE_STATIC"])
 def test_20_range_is_not_static_name(self):
    m=replace(Method(),2,name="invoke-static/range")
    q=mod.p245_checks(m)
    self.assertEqual((q["counts"]["INVOKE_STATIC_COUNT"],
                      q["counts"]["INVOKE_STATIC_RANGE_COUNT"]),(1,1))
    self.assertFalse(q["predicates"]["TWO_INVOKE_STATIC"])
 def test_21_getter_text_false(self):
    m=replace(Method(),1,output="WRONG_LOOKUP")
    self.assertFalse(mod.p245_checks(m)["predicates"]["GETTER_OUTPUT_PRESENT"])
 def test_22_log_text_false(self):
    m=replace(Method(),2,output="WRONG_LOG_REFERENCE")
    self.assertFalse(mod.p245_checks(m)["predicates"]["LOG_I_OUTPUT_PRESENT"])
 def test_23_raw_method_pool_both(self):
    m=Method();q=mod.p245_checks(m)
    self.assertEqual(mod.call_reference(m,q["rows"],Dex()),"BOTH_EXACT")
 def test_24_raw_pool_getter_changed(self):
    d=Dex();d.refs[1]=(mod.LOG[0],"different",mod.LOG[2:])
    m=Method()
    self.assertEqual(mod.call_reference(m,mod.p245_checks(m)["rows"],d),
                     "ONE_OR_MORE_DIFFER")
 def test_25_raw_pool_missing(self):
    d=Dex({});m=Method()
    self.assertEqual(mod.call_reference(m,mod.p245_checks(m)["rows"],d),
                     "UNVERIFIED")
 def test_26_raw_instruction_wrong_opcode(self):
    m=replace(Method(),1,raw=b"xxxxxx")
    self.assertEqual(mod.call_reference(m,mod.p245_checks(m)["rows"],Dex()),
                     "UNVERIFIED")
 def test_27_outs_frame_small(self):
    m=Method(outs=1)
    self.assertEqual(mod.call_reference(m,mod.p245_checks(m)["rows"],Dex()),
                     "UNVERIFIED")
 def test_28_typed_throwable_catch_valid(self):
    m=Method()
    with patch.object(mod,"decode",return_value=fake_decoded()):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "ONE_TYPED_THROWABLE_MOVE_EXCEPTION")
 def test_29_wrong_typed_handler(self):
    m=Method()
    with patch.object(mod,"decode",return_value=fake_decoded("badtype")):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "DIFFERENT")
 def test_30_catchall_not_equivalent(self):
    m=Method()
    with patch.object(mod,"decode",return_value=fake_decoded("catchall")):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "DIFFERENT")
 def test_31_multiple_typed_not_equivalent(self):
    m=Method()
    with patch.object(mod,"decode",return_value=fake_decoded("extra")):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "DIFFERENT")
 def test_32_handler_entry_wrong_opcode(self):
    m=replace(Method(),3,name="nop")
    with patch.object(mod,"decode",return_value=fake_decoded()):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "DIFFERENT")
 def test_33_handler_decode_error_unverified(self):
    m=Method()
    with patch.object(mod,"decode",side_effect=RuntimeError("PRIVATE")):
        self.assertEqual(mod.catch_profile(m,Dex(),mod.p245_checks(m)["rows"]),
                         "UNVERIFIED")
 def test_34_emit_redacted_always_deny(self):
    out=io.StringIO()
    with contextlib.redirect_stdout(out):
        self.assertEqual(mod.emit(valid()),2)
    self.assertIn("P281_P245_COMBINED_PREDICATE=PASS",out.getvalue())
    self.assertIn("P281_RELEASE=DENY",out.getvalue())
    self.assertNotIn(mod.GETTER_OUTPUT,out.getvalue())
 def test_35_forged_status_rejected(self):
    q=valid();q["predicates"]["ONE_TRY"]="OVERRIDE"
    with self.assertRaises(Deny):mod.emit(q)
 def test_36_inconsistent_count_rejected(self):
    q=valid();q["counts"]["TRY_COUNT"]=4
    with self.assertRaises(Deny):mod.emit(q)
 def test_37_source_only_does_not_claim_real(self):
    old=sys.argv;sys.argv=["p281"]
    try:
        out=io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(mod.main(),0)
        self.assertIn("P281_REAL_HELPER_CONDITIONS=NOT_ATTESTED",out.getvalue())
    finally:
        sys.argv=old

if __name__=="__main__":
    unittest.main()
