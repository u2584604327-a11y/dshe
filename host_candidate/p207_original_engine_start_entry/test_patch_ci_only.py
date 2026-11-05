#!/usr/bin/env python3
"""P207 16 tests of exact signature-bound, reversible one-opcode patch."""
import unittest
import patch_ci_only as p
DESC="(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"
def smali():
    return "\n".join([
       ".class public final Lcom/dsh/android/EngineManager;",
       ".super Ljava/lang/Object;",
       ".method public final start"+DESC,
       "    .locals 4",
       "    .line 13",
       "    :try_start_0",
       "    move-object v0, p0",
       "    if-eqz v0, :done",
       "    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;",
       "    :done",
       "    return-object v0",
       "    :try_end_0",
       "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_err",
       "    :catch_err",
       "    return-object v0",
       ".end method",
       ".method public final untouched()V",
       "    .locals 0",
       "    return-void",
       ".end method",
    ])+"\n"
def builder(double=False,java=True):
    anchor='if test "\${P72_ACCESSOR_FIXTURE_ONLY:-0}" = 1; then\n  test "\${P51_SIDE_BY_SIDE:-0}" = 1 || {'
    line="  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \\\n"
    return "start\n"+anchor*(2 if double else 1)+(line if java else "")
class Tests(unittest.TestCase):
    def deny(self,reason,fn):
        with self.assertRaises(p.Refused) as cm:fn()
        self.assertEqual(str(cm.exception),"P207_DENY_"+reason)
    def test_single_marker(self):
        self.assertEqual(p.patch_original_smali(smali(),DESC).count(p.INSERT.strip()),1)
    def test_inverse(self):
        self.assertEqual(p.patch_original_smali(smali(),DESC).replace(p.INSERT,"",1),smali())
    def test_early(self):
        self.assertLess(p.patch_original_smali(smali(),DESC).index(p.INSERT),
                        p.patch_original_smali(smali(),DESC).index(":try_start_0"))
    def test_flow(self):
        for tag in (":done","if-eqz v0", ".catch Ljava/lang/Exception;"):
            self.assertEqual(p.patch_original_smali(smali(),DESC).count(tag),smali().count(tag))
    def test_next_method_preserved(self):
        self.assertEqual(p.patch_original_smali(smali(),DESC).split(".method public final untouched",1)[1],
                         smali().split(".method public final untouched",1)[1])
    def test_wrong_descriptor(self):
        self.deny("EXACT_DEX_SMALI_SIGNATURE_MATCH",lambda:p.patch_original_smali(smali(),"()V"))
    def test_wrong_method(self):
        self.deny("EXACT_SINGLE_ORIGINAL_START_METHOD",lambda:p.patch_original_smali(
            smali().replace(" start"+DESC," boot"+DESC),DESC))
    def test_overload(self):
        self.deny("EXACT_SINGLE_ORIGINAL_START_METHOD",lambda:p.patch_original_smali(
            smali().replace(".method public final untouched()V",".method public final start()V"),DESC))
    def test_duplicate(self):
        self.deny("EXACT_SINGLE_ORIGINAL_START_METHOD",lambda:p.patch_original_smali(smali()+smali(),DESC))
    def test_double_marker(self):
        self.deny("ORIGINAL_ALREADY_INSTRUMENTED",lambda:p.patch_original_smali(
            p.patch_original_smali(smali(),DESC),DESC))
    def test_missing_locals(self):
        self.deny("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(
            smali().replace("    .locals 4\n",""),DESC))
    def test_double_locals(self):
        self.deny("EXACT_REGISTER_DIRECTIVE",lambda:p.patch_original_smali(
            smali().replace("    .locals 4\n","    .locals 4\n    .registers 8\n"),DESC))
    def test_short_method(self):
        self.deny("START_METHOD_BYTES_BOUND",lambda:p.patch_original_smali(
            ".method public final start"+DESC+"\n    .locals 0\n    return-object p0\n.end method\n",DESC))
    def test_builder_single(self):
        b=p.patch_builder(builder())
        self.assertEqual(b.count("patch_ci_only.py --inject-smali"),1)
        self.assertEqual(b.count("P207EngineStartEntryWitness.java"),1)
    def test_builder_duplicate(self):
        self.deny("EXPECTED_ONE_BUILDER_HOOK",lambda:p.patch_builder(builder(double=True)))
    def test_builder_java_missing(self):
        self.deny("EXPECTED_ONE_JAVA_COMPILE",lambda:p.patch_builder(builder(java=False)))
if __name__=="__main__":unittest.main(verbosity=2)
