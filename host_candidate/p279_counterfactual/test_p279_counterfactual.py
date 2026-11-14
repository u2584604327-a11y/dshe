#!/usr/bin/env python3
"""P279 CI-only P245 helper log value A/B fixture, source-only."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p279_counterfactual",
             "host_candidate/p245_build_only_probe",
             "host_candidate/p249_dual_diff",
             "host_candidate/p246_exception_semantics"]
import p245_build_only_probe as p245
from p246_exception_semantics import Deny
from p279_counterfactual import (
 choose_literals,convert_helper,TAG_ALLOWLIST,NON_NULL,NULL,
 OLD_TAG,OLD_YES,OLD_NO,main
)
def baseline():
 return (".class public final "+p245.OWNER+"\n"
         ".field public final synthetic this$0:Lcom/dsh/android/EngineManager;\n"
         ".method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;\n"
         +p245.OLD+"\n"
         "    invoke-static {v0}, "+p245.GETTER+"\n"
         ".end method\n")
def ephemeral():
 return p245.patched(baseline())
class Tests(unittest.TestCase):
 def test_01_synthetic_original_patch_works(self):
    self.assertIn(p245.NEW,ephemeral())
 def test_02_tag_prioritized(self):
    self.assertEqual(choose_literals({"MainActivity","DSH","true","false"}),
                     ("DSH","true","false"))
 def test_03_tag_fallback(self):
    self.assertEqual(choose_literals({"MainActivity","true","false"}),
                     ("MainActivity","true","false"))
 def test_04_android_tag(self):
    self.assertEqual(choose_literals({"Android","true","false"}),
                     ("Android","true","false"))
 def test_05_log_tag(self):
    self.assertEqual(choose_literals({"Log","true","false"}),
                     ("Log","true","false"))
 def test_06_no_safe_tag_denied(self):
    self.assertIsNone(choose_literals({"UNKNOWN","true","false"}))
 def test_07_no_true_denied(self):
    self.assertIsNone(choose_literals({"DSH","false"}))
 def test_08_no_false_denied(self):
    self.assertIsNone(choose_literals({"DSH","true"}))
 def test_09_binary_wrong_pool_denied(self):
    self.assertIsNone(choose_literals({"DSH",b"true","false"}))
 def test_10_wrong_container_denied(self):
    self.assertIsNone(choose_literals("DSHtruefalse"))
 def test_11_exact_helper_prefix_unchanged(self):
    a=ephemeral();b=convert_helper(a,("DSH","true","false"))
    self.assertTrue(b.startswith(a[:-len(p245.helper(p245.captured(a)))]))
 def test_12_helper_still_has_getter(self):
    self.assertIn(p245.GETTER,convert_helper(ephemeral(),("DSH","true","false")))
 def test_13_helper_still_logs(self):
    self.assertIn("Landroid/util/Log;->i",
                 convert_helper(ephemeral(),("DSH","true","false")))
 def test_14_same_byte_width_call_preserved(self):
    self.assertIn(p245.NEW,convert_helper(ephemeral(),("DSH","true","false")))
 def test_15_original_old_call_not_resurrected(self):
    self.assertNotIn(p245.OLD,convert_helper(ephemeral(),("DSH","true","false")))
 def test_16_log_tag_both_branches(self):
    self.assertEqual(convert_helper(ephemeral(),("DSH","true","false")).count(
                     '    const-string v1, "DSH"'),2)
 def test_17_true_and_false_once(self):
    b=convert_helper(ephemeral(),("DSH","true","false"))
    self.assertEqual((b.count('    const-string v2, "true"'),
                      b.count('    const-string v2, "false"')),(1,1))
 def test_18_no_new_p245_strings_in_helper(self):
    b=convert_helper(ephemeral(),("DSH","true","false"))
    self.assertNotIn(OLD_TAG,b);self.assertNotIn(OLD_YES,b)
    self.assertNotIn(OLD_NO,b)
 def test_19_helper_suffix_remains_bounded(self):
    a=ephemeral();b=convert_helper(a,("DSH","true","false"))
    self.assertLess(len(b),len(a))
    self.assertEqual(b.count(".method public static "+p245.NAME),1)
 def test_20_wrong_tag_rejected(self):
    with self.assertRaises(Deny):
        convert_helper(ephemeral(),("PRIVATE","true","false"))
 def test_21_incorrect_polarity_rejected(self):
    with self.assertRaises(Deny):
        convert_helper(ephemeral(),("DSH","false","true"))
 def test_22_unpatched_old_source_rejected(self):
    with self.assertRaises(Deny):
        convert_helper(baseline(),("DSH","true","false"))
 def test_23_unrelated_modified_smali_rejected(self):
    a=ephemeral().replace(OLD_YES,"    const-string v2, \"private\"")
    with self.assertRaises(Deny):
        convert_helper(a,("DSH","true","false"))
 def test_24_missing_helper_suffix_rejected(self):
    a=ephemeral().replace(".end method\n",".end method\n",1) +" extra"
    with self.assertRaises(Deny):
        convert_helper(a,("DSH","true","false"))
 def test_25_source_only_no_runtime_claim(self):
    old=sys.argv;sys.argv=["p279"]
    try:
     out=io.StringIO()
     with contextlib.redirect_stdout(out):self.assertEqual(main(),0)
     self.assertIn("P279_REAL_BASE_POOL_AND_HELPER=NOT_ATTESTED",out.getvalue())
     self.assertIn("P279_RELEASE=DENY",out.getvalue())
    finally:sys.argv=old
if __name__=="__main__":unittest.main()
