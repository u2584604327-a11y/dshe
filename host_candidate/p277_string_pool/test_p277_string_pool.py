#!/usr/bin/env python3
"""P277 source-only negative, boundary, rank and redaction test fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p277_string_pool","host_candidate/p275_encoding_width",
             "host_candidate/p249_dual_diff","host_candidate/p246_exception_semantics"]
from p246_exception_semantics import Deny
from p277_string_pool import (
    indexed_strings,pool_diff,crossing,emit,main,CAUSES
)
class FakeDex:
 def __init__(self,strings):self.values=strings
 def get_strings(self):return self.values
 def get_cm_string(self,i):return self.values[i]
class WrongIndex(FakeDex):
 def get_cm_string(self,i):return "PRIVATE_INDEX_WRONG"
class BadStrings:
 def get_strings(self):raise ValueError("PRIVATE_SHOULD_NOT_LOG")
class Op:
 def __init__(self,raw):self.raw=raw
 def get_raw(self):return self.raw
def row(jumbo,index,reg=0):
 name="const-string/jumbo" if jumbo else "const-string"
 op=0x1b if jumbo else 0x1a
 return (0,name,6 if jumbo else 4,Op(bytes([op,reg])+
       index.to_bytes(4 if jumbo else 2,"little")))
def corpus():
 a=tuple("STR"+str(i) for i in range(65536))
 b=("A_NEW",)+a
 return a,b
def fixture(a=None,b=None,old_index=65535,new_index=65536,reg_a=1,reg_b=1):
 if a is None or b is None:
    a,b=corpus()
 da,db=FakeDex(a),FakeDex(b)
 diff=pool_diff(a,b)
 x,y=row(False,old_index,reg_a),row(True,new_index,reg_b)
 return crossing(x,y,da,db,a,b,diff)
def payload():
 return dict(causes={k:int(k=="EXACT_INSERTION_ONLY_SHIFT") for k in CAUSES},
     checked=1,base_count=65536,new_count=65537,added_count=1,
     removed_count=0,pool_seal="EXACT_ID_ORDER_VERIFIED",
     preceding_additions="ADDED_BEFORE_EVERY_CROSSING",
     code_gate="DENY",exception_gate="DENY")
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
    cls.orig,cls.derived=corpus()
 def test_01_pool_addressability(self):
    self.assertEqual(indexed_strings(FakeDex(("a","b"))),("a","b"))
 def test_02_wrong_index_api_denied(self):
    self.assertIsNone(indexed_strings(WrongIndex(("a","b"))))
 def test_03_duplicate_pool_denied(self):
    self.assertIsNone(indexed_strings(FakeDex(("x","x"))))
 def test_04_malformed_pool_denied(self):
    self.assertIsNone(indexed_strings(FakeDex((1,2))))
 def test_05_pool_getter_exception_denied(self):
    self.assertIsNone(indexed_strings(BadStrings()))
 def test_06_empty_pool_denied(self):
    self.assertIsNone(indexed_strings(FakeDex(())))
 def test_07_added_exact_one(self):
    d=pool_diff(self.orig,self.derived)
    self.assertEqual((len(d["added"]),len(d["removed"])),(1,0))
 def test_08_common_order_preserved(self):
    self.assertTrue(pool_diff(self.orig,self.derived)["common_order"])
 def test_09_pool_common_order_reordered(self):
    d=pool_diff(("x","y"),("y","x","z"))
    self.assertFalse(d["common_order"])
 def test_10_pool_added_removed(self):
    d=pool_diff(("x","y","z"),("x","w","z"))
    self.assertEqual((len(d["added"]),len(d["removed"])),(1,1))
 def test_11_pool_duplicate_denied(self):
    self.assertIsNone(pool_diff(("a",),("b","b")))
 def test_12_pool_absent_denied(self):
    self.assertIsNone(pool_diff(None,("a",)))
 def test_13_exact_string_crossing(self):
    self.assertEqual(fixture(a=self.orig,b=self.derived),
                     ("EXACT_INSERTION_ONLY_SHIFT",1))
 def test_14_jumbo_promotion_not_low_index(self):
    self.assertEqual(fixture(a=("A",),b=("NEW","A"),old_index=0,
      new_index=1)[0],"NONCROSSING_OR_NOT_JUMBO")
 def test_15_raw_register_changed(self):
    self.assertEqual(fixture(a=self.orig,b=self.derived,reg_b=2)[0],
                     "REGISTER_CHANGED")
 def test_16_unreadable_index(self):
    self.assertEqual(fixture(a=self.orig,b=self.derived,new_index=65537)[0],
                     "RAW_INDEX_OR_POOL_UNVERIFIED")
 def test_17_pool_rank_mismatch(self):
    a,b=self.orig,self.derived
    d=pool_diff(a,b)
    d["added"]=set()
    self.assertEqual(crossing(row(False,65535,1),row(True,65536,1),
         FakeDex(a),FakeDex(b),a,b,d)[0],"RANK_EQUATION_FAILED")
 def test_18_pool_reorder_category(self):
    a,b=self.orig,self.derived
    d=pool_diff(a,b);d["common_order"]=False
    self.assertEqual(crossing(row(False,65535,1),row(True,65536,1),
         FakeDex(a),FakeDex(b),a,b,d)[0],"COMMON_ORDER_CHANGED")
 def test_19_pool_removed_before_target(self):
    a=list(self.orig)
    a[0]="TO_REMOVE"
    b=tuple(["NEW_FIRST","NEW_SECOND"]+[v for v in a if v!="TO_REMOVE"])
    result=fixture(a=tuple(a),b=b,old_index=65535,new_index=65536)
    self.assertEqual(result,("EXACT_INSERTION_MINUS_REMOVAL_SHIFT",2))
 def test_20_pool_remove_wrong_index_unverified(self):
    a=self.orig;b=self.derived
    self.assertEqual(fixture(a=a,b=b,old_index=65534,new_index=65536)[0],
                     "STRING_CONTENT_CHANGED")
 def test_21_nonconst_excluded(self):
    a,b=self.orig,self.derived
    first=(0,"move",2,Op(b""))
    self.assertEqual(crossing(first,row(True,65536),FakeDex(a),FakeDex(b),
         a,b,pool_diff(a,b))[0],"NONCROSSING_OR_NOT_JUMBO")
 def test_22_no_pool_seal_cannot_explain(self):
    a,b=self.orig,self.derived
    self.assertEqual(crossing(row(False,65535),row(True,65536),
         FakeDex(a),FakeDex(b),None,b,None)[0],
         "RAW_INDEX_OR_POOL_UNVERIFIED")
 def test_23_redacted_schema_deny(self):
    q=payload();out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(emit(q),2)
    self.assertIn("P277_CAUSE_EXACT_INSERTION_ONLY_SHIFT=1",out.getvalue())
    self.assertIn("P277_RELEASE=DENY",out.getvalue())
    self.assertNotIn("STR65535",out.getvalue())
 def test_24_forged_public_category_rejected(self):
    q=payload();q["causes"]["UNSAFE_PASS"]=1
    with self.assertRaises(Deny):emit(q)
 def test_25_bad_pool_counts_rejected(self):
    q=payload();q["added_count"]=2
    with self.assertRaises(Deny):emit(q)
 def test_26_gate_override_denied(self):
    q=payload();q["code_gate"]="PASS"
    with self.assertRaises(Deny):emit(q)
 def test_27_unverified_pool_cannot_claim_added(self):
    q=payload();q["pool_seal"]="UNVERIFIED"
    with self.assertRaises(Deny):emit(q)
 def test_28_source_only_no_real_assertion(self):
    old=sys.argv
    try:
     sys.argv=["p277"];out=io.StringIO()
     with contextlib.redirect_stdout(out):self.assertEqual(main(),0)
     self.assertIn("P277_REAL_POOL_ORDER=NOT_ATTESTED",out.getvalue())
    finally:sys.argv=old
if __name__=="__main__":unittest.main()
