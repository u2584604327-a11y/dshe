#!/usr/bin/env python3
"""P208 synthetic start$2 first marker and fail closed tests (no original assets)."""
import unittest
import patch_ci_only as p
DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
BR="Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
def fixture():
    return "\n".join([
       ".class final Lcom/dsh/android/EngineManager$start$2;",
       ".super Lkotlin/coroutines/jvm/internal/SuspendLambda;",
       ".method public final invokeSuspend"+DESC,
       "    .locals 5",
       "    .line 12",
       "    :try_start_0",
       "    iget v0, p0, Lcom/dsh/android/EngineManager$start$2;->label:I",
       "    if-eqz v0, :done",
       "    invoke-static {v0}, "+BR,
       "    :done",
       "    return-object p1",
       "    :try_end_0",
       "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch",
       "    :catch",
       "    return-object p1",
       ".end method",
       ".method public final another()V",
       "    .locals 0",
       "    return-void",
       ".end method"
    ])+"\n"
def builder(duplicated=False,java=True):
    anchor='if test "${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n  test "${P51_SIDE_BY_SIDE:-0}" = 1 || {'
    line="  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n"
    return "start\n"+anchor*(2 if duplicated else 1)+(line if java else "")
class Tests(unittest.TestCase):
    def deny(self,reason,fn):
        with self.assertRaises(p.Refused) as e:fn()
        self.assertEqual(str(e.exception),"P208_DENY_"+reason)
    def test_single(self):self.assertEqual(p.patch_original_smali(fixture()).count(p.INSERT.strip()),1)
    def test_inverse(self):self.assertEqual(p.patch_original_smali(fixture()).replace(p.INSERT,"",1),fixture())
    def test_entry_before_try(self):
        s=p.patch_original_smali(fixture());self.assertLess(s.index(p.INSERT),s.index(":try_start_0"))
    def test_branch_and_handler(self):
        s=p.patch_original_smali(fixture())
        for item in ("if-eqz",":try_start_0",".catch",":done"):
            self.assertEqual(s.count(item),fixture().count(item))
    def test_other_method_untouched(self):
        self.assertEqual(p.patch_original_smali(fixture()).split(".method public final another",1)[1],
                         fixture().split(".method public final another",1)[1])
    def test_wrong_method(self):
        self.deny("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
            lambda:p.patch_original_smali(fixture().replace(" invokeSuspend"," other")))
    def test_wrong_descriptor(self):
        self.deny("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
            lambda:p.patch_original_smali(fixture().replace(DESC,"()V")))
    def test_duplicate(self):
        self.deny("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",lambda:p.patch_original_smali(fixture()+fixture()))
    def test_double(self):
        self.deny("ORIGINAL_ALREADY_INSTRUMENTED",lambda:p.patch_original_smali(p.patch_original_smali(fixture())))
    def test_no_locals(self):
        self.deny("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(fixture().replace("    .locals 5\n","")))
    def test_two_locals(self):
        self.deny("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(fixture().replace("    .locals 5\n","    .locals 5\n    .registers 8\n")))
    def test_no_p40(self):
        self.deny("ORIGINAL_P40_BRIDGE_REQUIRED",lambda:p.patch_original_smali(fixture().replace(BR,"Lcom/dsh/android/Other;->start()V")))
    def test_original_processbuilder_denied(self):
        self.deny("ORIGINAL_P40_BRIDGE_REQUIRED",lambda:p.patch_original_smali(fixture().replace(BR,"Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;")))
    def test_second_p40_denied(self):
        self.deny("ORIGINAL_P40_BRIDGE_REQUIRED",lambda:p.patch_original_smali(fixture().replace("    :done","    invoke-static {v0}, "+BR+"\n    :done")))
    def test_too_short(self):
        self.deny("SUSPEND_METHOD_BYTES_BOUND",lambda:p.patch_original_smali(
            ".method public final invokeSuspend"+DESC+"\n    .locals 0\n    invoke-static {v0}, "+BR+"\n    return-object p0\n.end method"))
    def test_builder(self):
        b=p.patch_builder(builder())
        self.assertEqual(b.count("patch_ci_only.py --inject-smali"),1)
        self.assertEqual(b.count("P208StartCoroutineWitness.java"),1)
    def test_double_builder(self):
        self.deny("EXPECTED_ONE_BUILDER_HOOK",lambda:p.patch_builder(builder(duplicated=True)))
    def test_missing_java(self):
        self.deny("EXPECTED_ONE_JAVA_COMPILE",lambda:p.patch_builder(builder(java=False)))
    def test_no_sensitive_marker(self):
        for word in ("ProcessBuilder","Bearer","password","Cookie","MediaProjection"):
            self.assertNotIn(word,p.INSERT)
        self.assertIn("invoke-static {}",p.INSERT)
    def test_exact_class(self):
        self.assertIn("/p208/P208StartCoroutineWitness;",p.INSERT)
    def test_only_one_text_instruction(self):
        self.assertEqual(len(p.patch_original_smali(fixture())),len(fixture())+len(p.INSERT))
if __name__=="__main__":unittest.main(verbosity=2)
