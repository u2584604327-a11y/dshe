#!/usr/bin/env python3
"""P205 synthetic smali only; never tests or reads a user's Android device."""
import unittest
import patch_ci_only as p

def fixture():
    pre=(".class public Lcom/dsh/android/MainActivity;\n"
         ".super Landroid/app/Activity;\n\n"
         ".method private final unrelated()V\n"
         "    .locals 0\n"
         "    return-void\n"
         ".end method\n\n")
    method=(".method private final bootEngine()V\n"
            "    .locals 1\n"
            "    .line 9\n"
            + "    .line 10\n"*14
            + "    new-instance v0, Lcom/dsh/android/MainActivity$bootEngine$1;\n"
            "    invoke-direct {v0}, Lcom/dsh/android/MainActivity$bootEngine$1;-><init>()V\n"
            "    return-void\n"
            ".end method\n")
    return pre+method+"\n.method private final later()V\n    .locals 0\n    return-void\n.end method\n"

class P205Tests(unittest.TestCase):
    def denied(self,code,fn):
        with self.assertRaises(p.Refused) as z:fn()
        self.assertEqual(str(z.exception),"P205_DENY_"+code)
    def test_one_method_entry_marker(self):
        self.assertEqual(p.patch_original_smali(fixture()).count(p.INSERT.strip()),1)
    def test_remove_probe_byteidentical(self):
        raw=fixture()
        self.assertEqual(p.patch_original_smali(raw).replace(p.INSERT,"",1),raw)
    def test_patches_only_expected_method(self):
        new=p.patch_original_smali(fixture())
        self.assertTrue(new.index(" bootEngine()V")<new.index(p.INSERT.strip())<new.index(" later()V"))
    def test_first_opcode_is_probe(self):
        new=p.patch_original_smali(fixture())
        self.assertLess(new.index(p.INSERT.strip()),new.index("new-instance"))
    def test_duplicate_method_denied(self):
        m=fixture()
        self.denied("EXACT_SINGLE_BOOTENGINE_VOID_METHOD",lambda:p.patch_original_smali(m+m))
    def test_already_instrumented_denied(self):
        self.denied("ORIGINAL_ALREADY_INSTRUMENTED",lambda:p.patch_original_smali(p.patch_original_smali(fixture())))
    def test_wrong_method_name_denied(self):
        self.denied("EXACT_SINGLE_BOOTENGINE_VOID_METHOD",lambda:p.patch_original_smali(fixture().replace(" bootEngine()V"," bootEngine2()V")))
    def test_wrong_descriptor_denied(self):
        self.denied("EXACT_SINGLE_BOOTENGINE_VOID_METHOD",lambda:p.patch_original_smali(fixture().replace(" bootEngine()V"," bootEngine(I)V")))
    def test_registers_missing_denied(self):
        self.denied("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(fixture().replace("    .locals 1\n","")))
    def test_duplicate_register_directive_denied(self):
        self.denied("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(fixture().replace("    .locals 1\n","    .locals 1\n    .registers 2\n")))
    def test_branch_rejected(self):
        self.denied("METHOD_BRANCH_TRY_OR_EXCEPTION_NOT_VERIFIED",
                    lambda:p.patch_original_smali(fixture().replace(
                        "    .line 9\n","    if-eqz v0, :cond_1\n    .line 9\n")))
    def test_try_handler_rejected(self):
        self.denied("METHOD_BRANCH_TRY_OR_EXCEPTION_NOT_VERIFIED",
                    lambda:p.patch_original_smali(fixture().replace(
                        "    .line 9\n","    .catchall {:try_start .. :try_end} :catch_all\n    .line 9\n")))
    def test_original_lambda_required(self):
        self.denied("ORIGINAL_BOOT_LAMBDA_REFERENCE_REQUIRED",
                    lambda:p.patch_original_smali(fixture().replace("MainActivity$bootEngine$1","MainActivity$other$1")))
    def test_constructor_required(self):
        self.denied("ORIGINAL_BOOT_LAMBDA_CONSTRUCTION",
                    lambda:p.patch_original_smali(fixture().replace("-><init>()V","->invoke()V")))
    def test_short_method_denied(self):
        self.denied("BOOT_METHOD_BYTES_BOUND",
                    lambda:p.patch_original_smali(fixture().replace("    .line 10\n"*14,"")))
    def test_builder_single_guard_and_class(self):
        orig=('header\n'
              'if test "${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n'
              '  test "${P51_SIDE_BY_SIDE:-0}" = 1 || {\nfi\n'
              '  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n')
        new=p.patch_builder(orig)
        self.assertEqual(new.count("patch_ci_only.py --inject-smali"),1)
        self.assertEqual(new.count("P205BootEntryWitness.java"),1)
    def test_duplicate_builder_hook_denied(self):
        orig=(('if test "${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n'
               + '  test "${P51_SIDE_BY_SIDE:-0}" = 1 || {\n')*2
              + '  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n')
        self.denied("EXPECTED_ONE_BUILDER_HOOK",lambda:p.patch_builder(orig))
    def test_builder_without_java_line_denied(self):
        self.denied("EXPECTED_ONE_JAVA_COMPILE",lambda:p.patch_builder(
            ('if test "${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n'
             + '  test "${P51_SIDE_BY_SIDE:-0}" = 1 || {')))
    def test_no_native_permission_or_host_start(self):
        src=p.patch_original_smali(fixture())
        for forbidden in ("ProcessBuilder","INTERNET","startOrDeny"):
            self.assertNotIn(forbidden,src)
    def test_no_raw_user_data_in_marker(self):
        for token in ("Cookie","Bearer","Node","secret"):
            self.assertNotIn(token,p.INSERT)

if __name__=="__main__":
    unittest.main(verbosity=2)
