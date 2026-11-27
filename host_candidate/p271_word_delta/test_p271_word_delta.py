#!/usr/bin/env python3
"""P271 34 strict, source-only 35c/3rc word-count, register and pool fixtures."""
import contextlib
import io
import sys
import unittest
sys.path[:0] = ["host_candidate/p271_word_delta",
                "host_candidate/p267_invoke_words",
                "host_candidate/p269_method_pool"]
from test_p267_invoke_words import row, Method
from test_p269_method_pool import Dex
from p246_exception_semantics import Deny
from p271_word_delta import (
    WORD_CATEGORIES, REF_CATEGORIES, PROTO_CATEGORIES, FRAME_CATEGORIES,
    WIDE_CATEGORIES, contiguous, pair_detail, emit, main
)
def fixed(regs=(1,2,3),kind="static",index=17):
    return row("invoke-"+kind,regs,index=index)
def ranged(regs=(1,2,3),kind="static",index=17):
    return row("invoke-"+kind+"/range",regs,index=index)
def check(x=None,y=None,a=None,b=None,da=None,db=None):
    x=fixed() if x is None else x
    y=ranged() if y is None else y
    a=Method() if a is None else a
    b=Method() if b is None else b
    da=Dex(proto=("(JI)","V")) if da is None else da
    db=Dex(proto=("(JI)","V")) if db is None else db
    return pair_detail(x,y,a,b,da,db)
def output_template():
    groups=(WORD_CATEGORIES,REF_CATEGORIES,PROTO_CATEGORIES,
            FRAME_CATEGORIES,WIDE_CATEGORIES)
    return {"counts":[{x:0 for x in g} for g in groups],
            "examined":1,"prior_unknown_methods":492,"prior_ref_unverified":1}
class Tests(unittest.TestCase):
 def test_01_contiguous_one(self):
    self.assertTrue(contiguous((4,)))
 def test_02_contiguous_empty(self):
    self.assertTrue(contiguous(()))
 def test_03_contiguous_valid(self):
    self.assertTrue(contiguous((3,4,5)))
 def test_04_contiguous_gap(self):
    self.assertFalse(contiguous((3,5,6)))
 def test_05_contiguous_duplicate(self):
    self.assertFalse(contiguous((3,3)))
 def test_06_same_count_words_match(self):
    self.assertEqual(check()[0],"SAME_COUNT_WORD_SEQUENCE_MATCH")
 def test_07_count_decrease(self):
    self.assertEqual(check(y=ranged((1,2)))[0],"COUNT_CHANGED")
 def test_08_count_increase(self):
    self.assertEqual(check(x=fixed((1,2)),y=ranged((1,2,3)))[0],"COUNT_CHANGED")
 def test_09_count_change_even_if_zero(self):
    self.assertEqual(check(x=fixed(()),y=ranged((1,2)))[0],"COUNT_CHANGED")
 def test_10_same_length_fixed_gap(self):
    self.assertEqual(check(x=fixed((1,3,4)))[0],
                     "SAME_COUNT_FIXED_NONCONTIGUOUS")
 def test_11_same_length_fixed_reverse(self):
    self.assertEqual(check(x=fixed((3,2,1)))[0],
                     "SAME_COUNT_FIXED_NONCONTIGUOUS")
 def test_12_same_length_contiguous_offset(self):
    self.assertEqual(check(y=ranged((2,3,4)))[0],
                     "SAME_COUNT_CONTIGUOUS_DIFFERENT")
 def test_13_same_length_contiguous_shift_back(self):
    self.assertEqual(check(x=fixed((2,3,4)))[0],
                     "SAME_COUNT_CONTIGUOUS_DIFFERENT")
 def test_14_reversed_encoding_order(self):
    self.assertEqual(check(x=ranged((2,3,4)),y=fixed((1,2,3)))[0],
                     "SAME_COUNT_CONTIGUOUS_DIFFERENT")
 def test_15_five_word_fixed_noncontiguous(self):
    self.assertEqual(check(x=fixed((0,1,2,4,5)),
                           y=ranged((0,1,2,3,4)),
                           da=Dex(proto=("(IIIII)","V")),
                           db=Dex(proto=("(IIIII)","V")))[0],
                     "SAME_COUNT_FIXED_NONCONTIGUOUS")
 def test_16_wrong_instruction_pair(self):
    self.assertEqual(check(x=fixed(),y=row("move",(1,2)))[0],
                     "ENCODING_UNSUPPORTED")
 def test_17_wrong_invoke_family(self):
    self.assertEqual(check(x=fixed(),y=ranged(kind="virtual"))[0],
                     "ENCODING_UNSUPPORTED")
 def test_18_corrupted_raw_fixed(self):
    x=fixed();x[3].raw=b"bad"
    self.assertEqual(check(x=x)[0],"RAW_UNREADABLE")
 def test_19_corrupted_raw_range(self):
    y=ranged();y[3].raw=b"abc"
    self.assertEqual(check(y=y)[0],"RAW_UNREADABLE")
 def test_20_reference_same_even_when_words_differ(self):
    q=check(y=ranged((2,3,4)))
    self.assertEqual((q[0],q[1]),("SAME_COUNT_CONTIGUOUS_DIFFERENT","POOL_MATCH"))
 def test_21_reference_different_even_when_count_changes(self):
    q=check(y=ranged((1,2)),db=Dex(proto=("(JI)","V"),name="OTHER"))
    self.assertEqual((q[0],q[1]),("COUNT_CHANGED","POOL_DIFFER"))
 def test_22_reference_unavailable_not_assumed_same(self):
    self.assertEqual(check(db=Dex(missing=True))[1],"POOL_UNREADABLE")
 def test_23_invalid_class_method_ref(self):
    self.assertEqual(check(da=Dex(cls="BAD"))[1],"POOL_UNREADABLE")
 def test_24_invalid_proto_fails_closed(self):
    self.assertEqual(check(da=Dex(proto=("(V)","V")),
                           db=Dex(proto=("(V)","V")))[2],
                     "INVALID_OR_UNKNOWN")
 def test_25_valid_proto(self):
    self.assertEqual(check()[2],"VALID_BOTH")
 def test_26_both_wide_valid(self):
    self.assertEqual(check()[4],"VALID_BOTH")
 def test_27_noncontig_wide_invalid(self):
    self.assertEqual(check(x=fixed((1,3,4)))[4],"INVALID_ANY")
 def test_28_word_count_diff_invalid_wide(self):
    self.assertEqual(check(y=ranged((1,2)))[4],"INVALID_ANY")
 def test_29_frame_mismatch(self):
    self.assertEqual(check(b=Method(65,12))[3],"DIFFERENT")
 def test_30_register_out_of_frame(self):
    self.assertEqual(check(a=Method(2,12),b=Method(2,12))[3],
                     "INVALID_OR_UNKNOWN")
 def test_31_outs_too_small(self):
    self.assertEqual(check(a=Method(64,2),b=Method(64,2))[3],
                     "INVALID_OR_UNKNOWN")
 def test_32_fixed_schema_redacts_ids_and_values(self):
    q=output_template()
    for obj,name in zip(q["counts"],("COUNT_CHANGED","POOL_MATCH","VALID_BOTH",
                                    "VALID_BOTH","INVALID_ANY")):
        obj[name]=1
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        self.assertEqual(emit(q),2)
    printed=buf.getvalue()
    self.assertIn("P271_WORDS_COUNT_CHANGED=1",printed)
    self.assertIn("P271_RELEASE=DENY",printed)
    self.assertNotIn("Lx/Test;",printed)
    self.assertNotIn("13123456",printed)
 def test_33_schema_rejects_spoofed_count(self):
    q=output_template()
    for obj in q["counts"]:obj[next(iter(obj))]=1
    q["counts"][0]["EXTRA_PRIVATE_REGISTER"]=1
    with self.assertRaises(Deny):emit(q)
 def test_34_source_only_no_art_assertion(self):
    old=sys.argv
    try:
        sys.argv=["p271"]
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(main(),0)
        self.assertIn("P271_REAL_WORD_DIFFERENCE=NOT_ATTESTED",buf.getvalue())
        self.assertIn("P271_RELEASE=DENY",buf.getvalue())
    finally:sys.argv=old
if __name__=="__main__":
    unittest.main()
