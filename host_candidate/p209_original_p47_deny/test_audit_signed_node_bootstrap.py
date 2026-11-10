#!/usr/bin/env python3
"""Fail-closed synthetic tests; never run or mutate the original Android app."""
import unittest
from audit_signed_node_bootstrap import (
    Denied,normalize_descriptor,is_suspend_candidate,node_call_classes,
    bounded_method_summary,callsite_shape)

class Fake:
    def __init__(self,op,output="",length=2):
        self.op,self.output,self.length=op,output,length
    def get_name(self):return self.op
    def get_output(self):return self.output
    def get_length(self):return self.length

DESC="(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"
CALL=("v12, v11, Lcom/dsh/android/termux/TermuxBootstrap;"
      "->installNodeRuntime"+DESC)
def site(call=CALL,result="v10",guard="v10, v2, -0010",op="if-ne",exit_op="return-object"):
    return (Fake("invoke-virtual",call,6),
            Fake("move-result-object",result),
            Fake(op,guard,4),
            Fake(exit_op,"v10"))

class NodeBootstrapTests(unittest.TestCase):
    def test_descriptor_normalization(self):
        self.assertEqual(normalize_descriptor("("+ " Lkotlin/coroutines/Continuation; ) Ljava/lang/Object;"),DESC)
    def test_suspend_syntax_only(self):
        self.assertTrue(is_suspend_candidate(DESC))
        self.assertFalse(is_suspend_candidate("()V"))
        self.assertFalse(is_suspend_candidate("(Lkotlin/coroutines/Continuation;)V"))
    def test_exact_original_p406_p418_shape(self):
        self.assertTrue(callsite_shape(*site(),DESC))
    def test_wrong_callee_rejected(self):
        with self.assertRaises(Denied):
            callsite_shape(*site(call=CALL.replace("installNodeRuntime","other")),DESC)
    def test_wrong_return_register_rejected(self):
        with self.assertRaises(Denied):callsite_shape(*site(result="v8"),DESC)
    def test_wrong_guard_rejected(self):
        with self.assertRaises(Denied):callsite_shape(*site(guard="v8, v2, -0010"),DESC)
    def test_wrong_opcode_rejected(self):
        with self.assertRaises(Denied):callsite_shape(*site(op="if-eq"),DESC)
        with self.assertRaises(Denied):callsite_shape(*site(exit_op="goto"),DESC)
    def test_bounded_returns_and_calls(self):
        rows=[(0,Fake("invoke-virtual","v0, Landroid/content/res/AssetManager;->open()V")),
              (6,Fake("if-eqz","v0, +0002")),
              (10,Fake("return-object","v0"))]
        returns,branches,counts=bounded_method_summary(rows,0)
        self.assertEqual(returns,[(10,"return-object")])
        self.assertEqual(branches,[(6,"if-eqz")])
        self.assertEqual(counts["ASSET_API"],1)
    def test_resource_classes_are_static_only(self):
        self.assertIn("COROUTINE_API",node_call_classes("v0, Lkotlin/coroutines/intrinsics/IntrinsicsKt;->getCOROUTINE_SUSPENDED()Ljava/lang/Object;"))
        self.assertIn("HASH_OR_CRYPTO_API",node_call_classes("v0, Ljava/security/MessageDigest;->digest()[B"))
        self.assertIn("PROCESS_EXEC_API",node_call_classes("v0, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"))
        self.assertEqual(node_call_classes("v0, Lcom/example/Unknown;->foo()V"),["OTHER_INVOKE"])
    def test_invalid_method_bounds_rejected(self):
        with self.assertRaises(Denied):bounded_method_summary([],0)
        with self.assertRaises(Denied):bounded_method_summary([(0,Fake("return-object","v0"))],257)
        with self.assertRaises(Denied):
            bounded_method_summary([(0,Fake("nop")),(0,Fake("return-object","v0"))],0)

if __name__=="__main__":unittest.main(verbosity=2)
