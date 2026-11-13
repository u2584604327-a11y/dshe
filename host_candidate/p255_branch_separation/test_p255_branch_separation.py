#!/usr/bin/env python3
"""P255 22 source-only fixtures to prevent false actual-branch-diff claims."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics",
             "host_candidate/p249_dual_diff",
             "host_candidate/p251_method_relation",
             "host_candidate/p253_cfg_ordinal"]
from p246_exception_semantics import Deny
from test_p253_cfg_ordinal import (
 D,START,OTHER,base,width,wrong_jump,wrong_handler,added,
 different_opcode,Op,Method,NAMES
)
from p255_branch_separation import inspect_pair,audit,emit

def check(a=None,b=None):
    return inspect_pair(base() if a is None else a,
                        width() if b is None else b,D,D)
def audit_pair(a=None,b=None,key=START):
    return audit({key:base() if a is None else a},
                 {key:width() if b is None else b},D,D)

def opcode_and_width(moved_branch=False):
    x=wrong_jump() if moved_branch else width()
    x.ops[0]=Op("const/16",2)
    return x

class Tests(unittest.TestCase):
 def test_01_width_changed_branch_same(self):
    q=check()
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("WIDTH_ONLY","ORDINALS_MATCH_ONLY","NO"))
 def test_02_opcode_changed_branch_same(self):
    q=check(base(),different_opcode())
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("OPCODE_CHANGED","ORDINALS_MATCH_ONLY","YES"))
 def test_03_opcode_and_width_changed_branch_same(self):
    q=check(base(),opcode_and_width())
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("OPCODE_CHANGED","ORDINALS_MATCH_ONLY","YES"))
 def test_04_opcode_changed_actual_branch_diff(self):
    q=check(base(),opcode_and_width(True))
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("OPCODE_CHANGED","ORDINALS_DIFFER","NO"))
 def test_05_width_only_actual_branch_diff(self):
    q=check(base(),wrong_jump())
    self.assertEqual((q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("ORDINALS_DIFFER","NO"))
 def test_06_exception_diff_branch_match(self):
    q=check(base(),wrong_handler())
    self.assertEqual((q["explicit_branch"],q["exception_ordinal"]),
                     ("ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"))
 def test_07_count_changed_branch_diff(self):
    q=check(base(),added())
    self.assertEqual((q["layout"],q["explicit_branch"]),("COUNT_CHANGED","ORDINALS_DIFFER"))
 def test_08_count_changed_trailing_only(self):
    x=base()
    y=Method(ops=[Op(n,2,3 if i==1 else 0) for i,n in enumerate(NAMES)]+[Op("nop")])
    q=check(x,y)
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("COUNT_CHANGED","ORDINALS_MATCH_ONLY","YES"))
 def test_09_opcode_changed_with_no_branches(self):
    a=Method(ops=[Op("const/4"),Op("return-void")],tries=[])
    b=Method(ops=[Op("const/16"),Op("return-void")],tries=[])
    q=check(a,b)
    self.assertEqual((q["layout"],q["explicit_branch"],q["legacy_branch_conflated"]),
                     ("OPCODE_CHANGED","NONE","NO"))
 def test_10_no_branch_no_exception(self):
    x=Method(ops=[Op("const/4"),Op("return-void")],tries=[])
    q=check(x,x)
    self.assertEqual((q["explicit_branch"],q["exception_ordinal"]),("NONE","NONE"))
 def test_11_target_group_unchanged(self):
    self.assertEqual(audit_pair()["group"],"START_COROUTINE")
 def test_12_other_original_method_group(self):
    self.assertEqual(audit_pair(key=OTHER)["group"],"OTHER_PRIMARY")
 def test_13_same_method_relation(self):
    self.assertEqual(audit_pair()["relation"],"SAME_METHOD")
 def test_14_size_changed_retains_deny(self):
    self.assertTrue(audit_pair()["size_changed"])
 def test_15_no_code_size_change(self):
    q=audit_pair(base(),base())
    self.assertEqual((q["group"],q["explicit_branch"]),("NONE","NONE"))
 def test_16_public_report_does_not_certify_full_cfg(self):
    x=audit_pair(base(),opcode_and_width())
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        self.assertEqual(emit(x),2)
    msg=buf.getvalue()
    self.assertIn("P255_P253_BRANCH_LABEL_CONFLATED=YES",msg)
    self.assertIn("P255_COMPLETE_NORMAL_CFG=NOT_ATTESTED",msg)
    self.assertIn("P255_UNCHANGED_P245_GATE=NOT_ATTESTED",msg)
    self.assertNotIn(START[0],msg)
 def test_17_public_parity_never_release(self):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        self.assertEqual(emit(audit_pair(base(),base())),0)
    self.assertIn("P255_V139=STRUCTURAL_BLOCKED",buf.getvalue())
 def test_18_false_public_enum_deny(self):
    x=audit_pair()
    x["explicit_branch"]="SAFE_ALL_CFG"
    with self.assertRaises(Deny):emit(x)
 def test_19_illegal_branch_into_instruction_midpoint_deny(self):
    ops=[Op(n,4 if i==2 else 2,2 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):check(base(),Method(ops,handler=5))
 def test_20_switch_payload_deny(self):
    ops=[Op("packed-switch" if i==1 else n) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):check(base(),Method(ops))
 def test_21_negative_invalid_target_deny(self):
    ops=[Op(n,2,-999 if i==1 else 0) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):check(base(),Method(ops))
 def test_22_unapproved_added_method_deny(self):
    with self.assertRaises(Deny):
        audit({START:base()},{START:width(),OTHER:base()},D,D)
if __name__=="__main__":unittest.main()
