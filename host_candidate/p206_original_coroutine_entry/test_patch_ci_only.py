#!/usr/bin/env python3
"""P206 synthetic method-entry/CI fail-closed regressions; no real APK here."""
import unittest
import patch_ci_only as p

ENGINE="Lcom/dsh/android/EngineManager;->start("
def fixture():
    lines=[
       ".class final Lcom/dsh/android/MainActivity$bootEngine$1;",
       ".super Lkotlin/coroutines/jvm/internal/SuspendLambda;",
       ".method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
       "    .locals 3",
    ]+["    .line 11"]*16+[
       "    :try_start_0",
       "    iget v0, p0, Lcom/dsh/android/MainActivity$bootEngine$1;->label:I",
       "    if-eqz v0, :cond_zero",
       "    invoke-virtual {v0}, Lcom/dsh/android/EngineManager;->start()V",
       "    :cond_zero",
       "    return-object p1",
       "    :try_end_0",
       "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_err",
       "    :catch_err",
       "    return-object p1",
       ".end method",
       ".method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;",
       "    .locals 0",
       "    return-object p0",
       ".end method",
    ]
    return "\n".join(lines)+"\n"

def builder(single=True,with_java=True):
    anchor=('if test "${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n'
            '  test "${P51_SIDE_BY_SIDE:-0}" = 1 || {\n')
    line=('  host_candidate/p43_original_service/android/com/dsh/android/p43/'
          'P43ProbeActivity.java \\\n')
    return "start\n"+anchor*(1 if single else 2)+(line if with_java else "")

class Tests(unittest.TestCase):
    def refuse(self,label,f):
        with self.assertRaises(p.Refused) as e:f()
        self.assertEqual(str(e.exception),"P206_DENY_"+label)
    def test_one_marker_only(self):
        self.assertEqual(p.patch_original_smali(fixture()).count(p.INSERT.strip()),1)
    def test_exact_inverse_returns_original_text(self):
        original=fixture()
        self.assertEqual(p.patch_original_smali(original).replace(p.INSERT,"",1),original)
    def test_marker_precedes_original_try_label(self):
        result=p.patch_original_smali(fixture())
        self.assertLess(result.index(p.INSERT.strip()),result.index(":try_start_0"))
    def test_original_control_flow_and_handler_unchanged(self):
        result=p.patch_original_smali(fixture())
        for line in (":try_start_0","if-eqz v0, :cond_zero",
                     ".catch Ljava/lang/Exception;","return-object p1"):
            self.assertEqual(result.count(line),fixture().count(line))
    def test_neighbor_create_method_untouched(self):
        original=fixture()
        a=p.patch_original_smali(original).split(".method public final create(",1)[1]
        b=original.split(".method public final create(",1)[1]
        self.assertEqual(a,b)
    def test_wrong_method_name_denied(self):
        self.refuse("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
           lambda:p.patch_original_smali(fixture().replace(" invokeSuspend("," invokeOther(")))
    def test_wrong_method_descriptor_denied(self):
        self.refuse("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
           lambda:p.patch_original_smali(fixture().replace(
              "invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
              "invokeSuspend()Ljava/lang/Object;")))
    def test_duplicate_method_denied(self):
        original=fixture()
        self.refuse("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
           lambda:p.patch_original_smali(original+"\n"+original))
    def test_reentry_marker_denied(self):
        self.refuse("ORIGINAL_ALREADY_INSTRUMENTED",
           lambda:p.patch_original_smali(p.patch_original_smali(fixture())))
    def test_missing_locals_denied(self):
        self.refuse("EXACT_REGISTER_DIRECTIVE",
           lambda:p.patch_original_smali(fixture().replace("    .locals 3\n","")))
    def test_duplicate_register_directive_denied(self):
        self.refuse("EXACT_REGISTER_DIRECTIVE",
           lambda:p.patch_original_smali(fixture().replace(
               "    .locals 3\n","    .locals 3\n    .registers 7\n")))
    def test_expected_original_engine_callsite_required(self):
        self.refuse("ORIGINAL_ENGINE_START_CALLSITE_REQUIRED",
           lambda:p.patch_original_smali(fixture().replace(ENGINE,"Lcom/dsh/android/Other;->start(")))
    def test_short_suspend_method_denied(self):
        small="\n".join([
            ".method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;",
            "    .locals 1",
            "    invoke-virtual {v0}, Lcom/dsh/android/EngineManager;->start()V",
            "    return-object p1",
            ".end method",
        ])+"\n"
        self.refuse("SUSPEND_METHOD_BYTES_BOUND",
                    lambda:p.patch_original_smali(small))
    def test_builder_exclusive_p72_anchor(self):
        result=p.patch_builder(builder())
        self.assertEqual(result.count("patch_ci_only.py --inject-smali"),1)
        self.assertEqual(result.count("P206CoroutineEntryWitness.java"),1)
    def test_builder_double_matching_anchor_denied(self):
        self.refuse("EXPECTED_ONE_BUILDER_HOOK",
           lambda:p.patch_builder(builder(single=False)))
    def test_builder_missing_java_compile_line_denied(self):
        self.refuse("EXPECTED_ONE_JAVA_COMPILE",
           lambda:p.patch_builder(builder(with_java=False)))
    def test_production_launch_not_authorized(self):
        source=p.patch_original_smali(fixture())
        self.assertNotIn("ProcessBuilder",p.INSERT)
        self.assertNotIn("MediaProjection",p.INSERT)
        self.assertNotIn("INTERNET",p.INSERT)
        self.assertEqual(source.count(p.INSERT.strip()),1)
    def test_marker_always_no_registers_or_personal_data(self):
        self.assertIn("invoke-static {}",p.INSERT)
        for forbidden in ("Bearer","Cookie","password","account","userdata"):
            self.assertNotIn(forbidden,p.INSERT)
    def test_another_class_descriptor_not_matching(self):
        self.refuse("EXACT_SINGLE_ORIGINAL_INVOKESUSPEND_METHOD",
            lambda:p.patch_original_smali(fixture().replace(
               "Ljava/lang/Object;)Ljava/lang/Object;","Ljava/lang/String;)Ljava/lang/Object;",1)))
    def test_marker_class_is_not_original_engine_manager(self):
        self.assertIn("/p206/P206CoroutineEntryWitness;",p.INSERT)
        self.assertNotIn("EngineManager;->start",p.INSERT)

if __name__=="__main__":
    unittest.main(verbosity=2)
