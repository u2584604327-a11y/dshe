#!/usr/bin/env python3
"""P269 20 bounded zero-word / method-pool / malformed API fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p269_method_pool","host_candidate/p267_invoke_words"]
from test_p267_invoke_words import row,Method,REF
from p246_exception_semantics import Deny
from p269_method_pool import (method_pool,library_zero_view,classify_pool,
                             CATEGORIES,emit,main)
class Dex:
 def __init__(self,proto=("()","V"),name="call",cls="Lx/Test;",missing=False):
    self.proto=proto;self.name=name;self.cls=cls;self.missing=missing
 def get_cm_method(self,index):
    if self.missing:raise LookupError("PRIVATE_REFS")
    return [self.cls,self.name,self.proto]
class NoApi:pass
def args(count=0,kind="static",regs=None):
    w=() if regs is None else regs
    a=row("invoke-"+kind,w)
    b=row("invoke-"+kind+"/range",w)
    return a,b
def omission(a):a[3].get_operands=lambda: []
def check(da=None,db=None,pair=None,ma=None,mb=None):
    a,b=args() if pair is None else pair
    omission(a)
    return classify_pool(a,b,ma or Method(),mb or Method(),da or Dex(),db or Dex())
class Tests(unittest.TestCase):
 def test_01_method_pool_exact_validated(self):
    self.assertEqual(method_pool(Dex(),17),("Lx/Test;","call","()","V"))
 def test_02_missing_ref_no_leak(self):
    self.assertIsNone(method_pool(Dex(missing=True),17))
 def test_03_bad_class_descriptor(self):
    self.assertIsNone(method_pool(Dex(cls="notclass"),17))
 def test_04_bad_method_name(self):
    self.assertIsNone(method_pool(Dex(name="x y"),17))
 def test_05_bad_proto_shape(self):
    self.assertIsNone(method_pool(Dex(proto="()V"),17))
 def test_06_zero_raw_word_count(self):
    a,b=args()
    self.assertEqual((a[3].get_raw()[1]>>4,b[3].get_raw()[1]),(0,0))
 def test_07_zero_fixed_missing_api_ref(self):
    a,b=args();omission(a)
    self.assertTrue(library_zero_view(a,17))
    self.assertFalse(library_zero_view(b,17))
 def test_08_zero_pool_identity_candidate(self):
    self.assertEqual(check(),"ZERO_WORD_35C_OMISSION_POOL_MATCH_CANDIDATE")
 def test_09_zero_pool_mismatch(self):
    self.assertEqual(check(db=Dex(name="different")),"ZERO_WORD_POOL_METHOD_DIFFER")
 def test_10_zero_missing_pool(self):
    self.assertEqual(check(db=Dex(missing=True)),"POOL_METHOD_REFERENCE_UNAVAILABLE")
 def test_11_zero_static_has_declared_arg(self):
    self.assertEqual(check(da=Dex(proto=("(I)","V")),db=Dex(proto=("(I)","V"))),
                     "ZERO_WORD_EXPECTED_ARGUMENTS_NONZERO")
 def test_12_zero_nonstatic_invalid(self):
    self.assertEqual(check(pair=args(kind="virtual")),"ZERO_WORD_NONSTATIC_RECEIVER_INVALID")
 def test_13_zero_no_library_omission(self):
    a,b=args()
    self.assertEqual(classify_pool(a,b,Method(),Method(),Dex(),Dex()),
                     "LIBRARY_REFERENCE_VIEW_NOT_RECONCILED")
 def test_14_nonzero_same_method_ref(self):
    pair=args(kind="static",regs=(1,2))
    ref=Dex(proto=("(II)","V"))
    self.assertEqual(check(pair=pair,da=ref,db=ref),
                     "NONZERO_METHOD_POOL_MATCH_CANDIDATE")
 def test_15_nonzero_wrong_register_sequence(self):
    a,b=args(regs=(1,2));b=row("invoke-static/range",(2,3))
    self.assertEqual(check(pair=(a,b)),"NONZERO_REGISTER_WORDS_DIFFER")
 def test_16_nonzero_invalid_wide(self):
    a,b=args(regs=(1,2,3))
    ref=Dex(proto=("(JI)","V"))
    self.assertEqual(check(pair=(a,b),da=ref,db=ref),
                     "NONZERO_METHOD_POOL_MATCH_CANDIDATE")
 def test_17_nonzero_wrong_width(self):
    a,b=args(regs=(1,2))
    ref=Dex(proto=("(JI)","V"))
    self.assertEqual(check(pair=(a,b),da=ref,db=ref),
                     "NONZERO_WIDE_LAYOUT_INVALID")
 def test_18_bad_raw_denied(self):
    a,b=args();a[3].raw=b"abcd"
    self.assertEqual(check(pair=(a,b)),"RAW_OR_ENCODING_UNVERIFIED")
 def test_19_sanitized_public_denial(self):
    c={k:0 for k in CATEGORIES};c["ZERO_WORD_35C_OMISSION_POOL_MATCH_CANDIDATE"]=1
    o=io.StringIO()
    with contextlib.redirect_stdout(o):
        self.assertEqual(emit(dict(counts=c,ref_unknown=1,prior_unknown=492,matched_candidates=0)),2)
    s=o.getvalue()
    self.assertIn("P269_RELEASE=DENY",s)
    self.assertNotIn("Lx/Test",s)
 def test_20_bad_count_fails_closed(self):
    c={k:0 for k in CATEGORIES};c["ZERO_WORD_35C_OMISSION_POOL_MATCH_CANDIDATE"]=2
    with self.assertRaises(Deny):
        emit(dict(counts=c,ref_unknown=1,prior_unknown=492,matched_candidates=0))
 def test_21_source_only_no_real_attestation(self):
    orig=sys.argv
    try:
        sys.argv=["p269"]
        o=io.StringIO()
        with contextlib.redirect_stdout(o):self.assertEqual(main(),0)
        self.assertIn("P269_REAL_METHOD_POOL=NOT_ATTESTED",o.getvalue())
    finally:sys.argv=orig
if __name__=="__main__":unittest.main()
