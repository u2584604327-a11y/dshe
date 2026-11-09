#!/usr/bin/env python3
import unittest
import patch_gate_ci_only as p
def original():
    return ("package com.dsh.android.p47;\n"+
       p.METHOD+p.SHAPE+
       "    validateOriginalStreams(builder,3);\n"+
       "    P150OriginalCoroutineObserver.recordFromP47();\n"+
       "    P149OriginalBuilderWitness.observeWithoutLaunch(builder,3);\n"+
       p.THROW+"  }\n"+p.NEXT+" probe config unchanged\n")
def builder():
    return (p.BEFORE+"if test \"P208_CI_METHOD_ENTRY_ONLY\" = 1; then\n"+
           "  "+p.P208_JAVA+" \\\n"+p.P208_HOOK)
class Tests(unittest.TestCase):
    def deny(self,code,func):
        with self.assertRaises(p.Deny) as cm:func()
        self.assertEqual(str(cm.exception),"P209_DENY_"+code)
    def test_add(self):self.assertEqual(p.patch_gate(original()).count(p.ENTER),1)
    def test_inverse(self):
        v=p.patch_gate(original())
        self.assertEqual(v.replace(p.ENTER,"",1).replace(p.STACK,"",1).replace(p.FINAL,"",1),original())
    def test_position(self):
        v=p.patch_gate(original())
        self.assertTrue(v.index(p.ENTER)<v.index(p.SHAPE)<v.index(p.STACK)<v.index(p.FINAL)<v.index(p.THROW))
    def test_other_method(self):
        self.assertEqual(p.patch_gate(original()).split(p.NEXT,1)[1],original().split(p.NEXT,1)[1])
    def test_duplicate(self):
        self.deny("ONE_PRIMARY_METHOD",lambda:p.patch_gate(original()+original()))
    def test_no_throw(self):
        self.deny("PRIMARY_ORIGINAL_DENY_ANCHORS",lambda:p.patch_gate(original().replace(p.THROW,"")))
    def test_no_shape(self):
        self.deny("PRIMARY_ORIGINAL_DENY_ANCHORS",lambda:p.patch_gate(original().replace(p.SHAPE,"")))
    def test_two_times(self):
        self.deny("NOT_ALREADY_MARKED",lambda:p.patch_gate(p.patch_gate(original())))
    def test_builder(self):
        self.assertIn(p.AFTER,p.patch_builder(builder()))
    def test_builder_inverse(self):
        v=p.patch_builder(builder())
        self.assertEqual(v.replace("  "+p.PRE_JAVA+" \\\n","",1).replace(p.P208_HOOK+p.P209_HOOK,p.P208_HOOK,1).replace(p.AFTER,p.BEFORE,1),builder())
    def test_wrong_builder(self):
        self.deny("PINNED_P208_BUILDER_REQUIRED",lambda:p.patch_builder("untrusted"))
    def test_duplicate_source(self):
        self.deny("PINNED_P208_BUILDER_REQUIRED",lambda:p.patch_builder(builder()+p.BEFORE))
    def test_no_process_spawn(self):
        self.assertNotIn("ProcessBuilder.start",p.ENTER+p.STACK+p.FINAL)
def p40_fixture():
    return (p.P40_HDR+'    .param p0, "builder" # Ljava/lang/ProcessBuilder;\n'+
      p.P40_CALL+'    move-result-object v0\n    return-object v0\n.end method\n')
class P40Tests(unittest.TestCase):
    def test_one_marker(self):
        s=p40_fixture();v=p.patch_p40(s)
        self.assertEqual(v.count("P209_P40_BRIDGE_ENTRY=OBSERVED"),1)
        self.assertEqual(v.replace(p.P40_LOG,"",1).replace(
           p.P40_HDR.replace(".registers 2",".registers 3"),p.P40_HDR,1),s)
    def test_no_original_call(self):
        with self.assertRaises(p.Deny):
            p.patch_p40(p40_fixture().replace(p.P40_CALL,""))
    def test_double_marker_denied(self):
        with self.assertRaises(p.Deny):
            p.patch_p40(p.patch_p40(p40_fixture()))
class VerifierTests(unittest.TestCase):
    def test_strict_p47_verifier_inverse(self):
        s="head\n"+p.VERIFY_OLD+"\ntail\n"
        result=p.patch_verifier(s)
        self.assertEqual(result.replace(p.VERIFY_NEW,p.VERIFY_OLD,1),s)
        self.assertIn("P209_EXACT_ONE_TEST_LOG_BEFORE_STRICT_P47",result)
    def test_missing_original_verifier_denied(self):
        with self.assertRaises(p.Deny):
            p.patch_verifier("not original")
def precall_fixture():
    import sys
    sys.path.insert(0,"host_candidate/p208_original_start_coroutine")
    import patch_ci_only as p208
    return (".class final Lcom/dsh/android/EngineManager$start$2;\n"+
      ".method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;\n"+
      "    .locals 4\n"+p208.INSERT+
      "    const/4 v0, 0x0\n"+
      "    if-ne v0, v1, :done\n"+
      "    const/4 v2, 0x0\n"+
      "    :done\n"+
      "    invoke-static/range {p1 .. p1}, Lkotlin/ResultKt;->throwOnFailure(Ljava/lang/Object;)V\n"+
      "    iget-object v2, p0, Lcom/dsh/android/EngineManager$start$2;->label:I\n"+
      "    invoke-static {v0}, "+p.P40_TARGET+"\n"+
      "    return-object v0\n.end method\n")
class PreCallTests(unittest.TestCase):
    def test_pre_call_exact_inverse(self):
        s=precall_fixture()
        self.assertEqual(p.inject_precall(s).replace(p.GUARD_INVOKE,"",1).replace(p.FALL_INVOKE,"",1).replace(p.TARGET_INVOKE,"",1).replace(p.PRE_INVOKE,"",1),s)
    def test_missing_p40_fails_closed(self):
        s=precall_fixture().replace(p.P40_TARGET,"Lcom/example/Other;->start()V")
        with self.assertRaises(p.Deny):p.inject_precall(s)
    def test_duplicate_p40_fails_closed(self):
        s=precall_fixture()
        call="    invoke-static {v0}, "+p.P40_TARGET+"\n"
        with self.assertRaises(p.Deny):p.inject_precall(s.replace(call,call+call))
    def test_duplicate_precall_fails_closed(self):
        with self.assertRaises(p.Deny):p.inject_precall(p.inject_precall(precall_fixture()))
    def test_first_guard_before_original_if_ne(self):
        value=p.inject_precall(precall_fixture())
        self.assertEqual(value.count(p.GUARD_INVOKE.strip()),1)
        self.assertLess(value.index(p.GUARD_INVOKE),value.index("    if-ne v0, v1, :done"))
        self.assertLess(value.index("    if-ne v0, v1, :done"),value.index(p.FALL_INVOKE))
        self.assertLess(value.index(p.FALL_INVOKE),value.index(p.PRE_INVOKE))
    def test_wrong_first_guard_refused(self):
        value=precall_fixture().replace("if-ne v0, v1","if-eq v0, v1")
        with self.assertRaises(p.Deny) as x:p.inject_precall(value)
        self.assertEqual(str(x.exception),"P209_DENY_SIGNED_FIRST_GUARD_OPCODE_AND_ORDER")
    def test_repeated_guard_refused(self):
        value=p.inject_precall(precall_fixture())
        with self.assertRaises(p.Deny):p.inject_precall(value)
    def test_dynamic_first_if_op_matches_exact_runtime_pin(self):
        value=precall_fixture().replace("if-ne v0, v1", "if-nez v0")
        result=p.inject_precall(value,expected_guard_op="if-nez")
        self.assertEqual(result.replace(p.GUARD_INVOKE,"",1).replace(p.FALL_INVOKE,"",1).replace(p.TARGET_INVOKE,"",1).replace(p.PRE_INVOKE,"",1),value)
    def test_fallthrough_marker_once_between_if_and_p40(self):
        result=p.inject_precall(precall_fixture())
        self.assertEqual(result.count(p.FALL_INVOKE.strip()),1)
        self.assertLess(result.index("    if-ne v0, v1, :done"),result.index(p.FALL_INVOKE))
        self.assertLess(result.index(p.FALL_INVOKE),result.index(p.PRE_INVOKE))
    def test_duplicate_fallthrough_marker_rejected(self):
        value=precall_fixture().replace("    return-object v0\n",
            p.FALL_INVOKE+"    return-object v0\n")
        with self.assertRaises(p.Deny) as x:p.inject_precall(value)
        self.assertEqual(str(x.exception),"P209_DENY_PRECALL_OR_GUARD_OR_FALL_OR_TARGET_ALREADY_MARKED")
    def test_pc176_postcall_marker_after_original_throw_and_before_iget(self):
        x=p.inject_precall(precall_fixture())
        self.assertEqual(x.count(p.TARGET_INVOKE.strip()),1)
        self.assertLess(x.index("    :done"),x.index("    invoke-static/range {p1 .. p1}"))
        self.assertLess(x.index("    invoke-static/range {p1 .. p1}"),x.index(p.TARGET_INVOKE))
        self.assertLess(x.index(p.TARGET_INVOKE),x.index("    iget-object v2, p0"))
        self.assertLess(x.index(p.TARGET_INVOKE),x.index(p.PRE_INVOKE))
        # A generic or relocated call is not an acceptable post-return witness.
        tampered=precall_fixture().replace(
            "Lkotlin/ResultKt;->throwOnFailure(Ljava/lang/Object;)V",
            "Lexample/Untrusted;->fake(Ljava/lang/Object;)V")
        with self.assertRaises(p.Deny) as e:p.inject_precall(tampered)
        self.assertEqual(str(e.exception),
            "P209_DENY_EXACT_SIGNED_PC176_THROWONFAILURE_FIRST_OPCODE")
    def test_no_first_branch_target_label_refused(self):
        x=precall_fixture().replace(":done",":missing",1)
        with self.assertRaises(p.Deny) as err:p.inject_precall(x)
        self.assertEqual(str(err.exception),"P209_DENY_ORIGINAL_IF_TAKEN_LABEL_UNIQUE")
if __name__=="__main__":unittest.main(verbosity=2)
