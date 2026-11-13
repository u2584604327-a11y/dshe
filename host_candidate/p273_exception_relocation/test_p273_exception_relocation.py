#!/usr/bin/env python3
"""P273 strictly synthetic redacted exception-relocation audit, 35 cases."""
import contextlib
import io
import sys
import unittest
sys.path[:0]=[
 "host_candidate/p273_exception_relocation",
 "host_candidate/p261_all_method_census",
 "host_candidate/p257_opcode_family",
 "host_candidate/p253_cfg_ordinal",
 "host_candidate/p251_method_relation",
 "host_candidate/p249_dual_diff",
 "host_candidate/p246_exception_semantics"
]
from p246_exception_semantics import Deny
from p273_exception_relocation import (
    MAP_CATEGORIES, ORDINAL_CATEGORIES, OPCODE_CATEGORIES,
    BRANCH_CATEGORIES, FRAME_CATEGORIES, SHIFT_CATEGORIES,
    private_row_mapping, translated_exception, shift_flags,
    ordinal_from_rows, provenance, emit, main
)
class Inst:
 def __init__(self,delta=None):self.delta=delta
 def get_ref_off(self):return self.delta
def original_rows():
 return [(0,"const/4",2,Inst()),(1,"invoke-static",6,Inst()),
         (4,"return-void",2,Inst())]
def candidate_rows():
 return [(0,"const/16",4,Inst()),(2,"invoke-static",6,Inst()),
         (5,"return-void",2,Inst())]
def make(start=0,end=4,target=4,kind="typed",total=5):
 handler=((("Lx/Err;",target),),None) if kind=="typed" else ((),target)
 return (total,((start,end-start,handler),))
def baseline():
 return (make(),make(end=5,target=5,total=6),
         original_rows(),candidate_rows())
def check(left=None,right=None,ra=None,rb=None,opaque=False,frame="MATCH"):
 a,b,rows_a,rows_b=baseline()
 return provenance(a if left is None else left,
                   b if right is None else right,
                   rows_a if ra is None else ra,
                   rows_b if rb is None else rb,
                   prior_opaque=opaque,frame_category=frame)
def all_counts():
 groups=(MAP_CATEGORIES,ORDINAL_CATEGORIES,OPCODE_CATEGORIES,
         BRANCH_CATEGORIES,FRAME_CATEGORIES)
 q={"counts":[{x:0 for x in names} for names in groups],
    "shifts":{x:0 for x in SHIFT_CATEGORIES},
    "original_code_methods":52014,"raw_exception_methods":1,
    "previous_exception_gate":"DENY"}
 for group,label in zip(q["counts"],(
     "EXACT_BOUNDARY_REMAP","SAME","ENCODING_FAMILY_ONLY","MATCH","MATCH")):
    group[label]=1
 return q

class Tests(unittest.TestCase):
 def test_01_reloc_mapping_start(self):
    a,b,ra,rb=baseline()
    self.assertEqual(private_row_mapping(a,b,ra,rb)[0],0)
 def test_02_reloc_mapping_later_instruction(self):
    a,b,ra,rb=baseline()
    self.assertEqual(private_row_mapping(a,b,ra,rb)[1],2)
 def test_03_reloc_mapping_target(self):
    a,b,ra,rb=baseline()
    self.assertEqual(private_row_mapping(a,b,ra,rb)[4],5)
 def test_04_reloc_mapping_end(self):
    a,b,ra,rb=baseline()
    self.assertEqual(private_row_mapping(a,b,ra,rb)[5],6)
 def test_05_remap_exact_typed(self):
    a,b,ra,rb=baseline()
    self.assertEqual(translated_exception(a,private_row_mapping(a,b,ra,rb)),b[1])
 def test_06_remap_exact_catchall(self):
    a,b,ra,rb=baseline()
    a=make(kind="catchall");b=make(end=5,target=5,kind="catchall",total=6)
    self.assertEqual(translated_exception(a,private_row_mapping(a,b,ra,rb)),b[1])
 def test_07_try_start_shift_relocates(self):
    a,b,ra,rb=baseline()
    a=make(start=1,end=4);b=make(start=2,end=5,target=5,total=6)
    self.assertEqual(translated_exception(a,private_row_mapping(a,b,ra,rb)),b[1])
 def test_08_ordinals_match_after_relocation(self):
    a,b,ra,rb=baseline()
    self.assertEqual(ordinal_from_rows(a,ra),ordinal_from_rows(b,rb))
 def test_09_try_start_raw_equal(self):
    a,b,_,_=baseline()
    self.assertFalse(shift_flags(a,b)["TRY_START"])
 def test_10_try_end_raw_shift(self):
    a,b,_,_=baseline()
    self.assertTrue(shift_flags(a,b)["TRY_END"])
 def test_11_typed_raw_target_shift(self):
    a,b,_,_=baseline()
    self.assertTrue(shift_flags(a,b)["TYPED_HANDLER_TARGET"])
 def test_12_size_shift(self):
    a,b,_,_=baseline()
    self.assertTrue(shift_flags(a,b)["CODE_SIZE"])
 def test_13_catchall_shift(self):
    a=make(kind="catchall")
    b=make(end=5,target=5,kind="catchall",total=6)
    self.assertTrue(shift_flags(a,b)["CATCHALL_HANDLER_TARGET"])
 def test_14_exact_map_category(self):
    self.assertEqual(check()["classes"][0],"EXACT_BOUNDARY_REMAP")
 def test_15_ordinal_match_category(self):
    self.assertEqual(check()["classes"][1],"SAME")
 def test_16_family_only_category(self):
    self.assertEqual(check()["classes"][2],"ENCODING_FAMILY_ONLY")
 def test_17_normal_branches_match(self):
    self.assertEqual(check()["classes"][3],"MATCH")
 def test_18_frame_match(self):
    self.assertEqual(check()["classes"][4],"MATCH")
 def test_19_frame_differ_recorded(self):
    self.assertEqual(check(frame="DIFFER")["classes"][4],"DIFFER")
 def test_20_frame_not_attested_recorded(self):
    self.assertEqual(check(frame="NOT_ATTESTED")["classes"][4],"NOT_ATTESTED")
 def test_21_opcode_kind_change_untrusted(self):
    b=candidate_rows()
    b[0]=(0,"new-instance",4,Inst())
    self.assertEqual(check(rb=b)["classes"][2],"OPERATION_KIND_CHANGED")
 def test_22_opaque_payload_no_false_remap(self):
    c=check(opaque=True)["classes"]
    self.assertEqual((c[0],c[2],c[3]),
                     ("UNVERIFIED_LAYOUT","OPAQUE_PAYLOAD_UNVERIFIED","UNVERIFIED"))
 def test_23_count_changed_not_remapped(self):
    a,b,ra,rb=baseline()
    rb=rb[:-1]
    self.assertEqual(check(rb=rb)["classes"][0],"UNVERIFIED_LAYOUT")
 def test_24_count_changed_opcode(self):
    a,b,ra,rb=baseline()
    self.assertEqual(check(rb=rb[:-1])["classes"][2],
                     "INSTRUCTION_COUNT_CHANGED")
 def test_25_try_changed_ordinal_unmatched(self):
    a,b,ra,rb=baseline()
    altered=make(start=2,end=5,target=5,total=6)
    v=check(right=altered)["classes"]
    self.assertEqual((v[0],v[1]),("MAPPED_TABLE_DIFFER","DIFFER"))
 def test_26_typed_descriptor_changed_is_not_relocation(self):
    a,b,ra,rb=baseline()
    b=(6,((0,5,((("Lx/Changed;",5),),None)),))
    self.assertEqual(check(right=b)["classes"][0],"MAPPED_TABLE_DIFFER")
 def test_27_typed_target_changed_is_not_relocation(self):
    a,b,ra,rb=baseline()
    b=make(end=5,target=2,total=6)
    self.assertEqual(check(right=b)["classes"][0],"MAPPED_TABLE_DIFFER")
 def test_28_catchall_wrong_target_denied(self):
    a=make(kind="catchall")
    b=make(end=5,target=2,kind="catchall",total=6)
    self.assertEqual(check(left=a,right=b)["classes"][0],"MAPPED_TABLE_DIFFER")
 def test_29_invalid_original_try_boundary(self):
    a,b,ra,rb=baseline()
    a=make(start=3,end=4)
    with self.assertRaises(Deny):check(left=a)
 def test_30_invalid_typed_target_boundary(self):
    a,b,ra,rb=baseline()
    a=make(target=3)
    with self.assertRaises(Deny):check(left=a)
 def test_31_invalid_catchall_boundary(self):
    a,b,ra,rb=baseline()
    a=make(target=3,kind="catchall")
    with self.assertRaises(Deny):check(left=a)
 def test_32_exact_raw_same_forbidden(self):
    a,b,ra,rb=baseline()
    with self.assertRaises(Deny):check(right=a,rb=ra)
 def test_33_public_output_redacted_and_deny(self):
    q=all_counts()
    o=io.StringIO()
    with contextlib.redirect_stdout(o):self.assertEqual(emit(q),2)
    s=o.getvalue()
    self.assertIn("P273_REMAP_EXACT_BOUNDARY_REMAP=1",s)
    self.assertIn("P273_RELEASE=DENY",s)
    self.assertNotIn("Lx/Err;",s)
 def test_34_public_schema_rejects_unknown(self):
    q=all_counts()
    q["counts"][0]["UNSAFE_ACCEPT"]=1
    with self.assertRaises(Deny):emit(q)
 def test_35_source_only_never_attests_real(self):
    old=sys.argv;sys.argv=["p273"]
    try:
     o=io.StringIO()
     with contextlib.redirect_stdout(o):self.assertEqual(main(),0)
     self.assertIn("P273_REAL_EXCEPTION_REMAP=NOT_ATTESTED",o.getvalue())
    finally:sys.argv=old
if __name__=="__main__":unittest.main()
