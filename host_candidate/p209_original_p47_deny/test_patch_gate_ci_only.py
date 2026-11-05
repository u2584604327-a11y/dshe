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
    return p.BEFORE+"if test \"P208_CI_METHOD_ENTRY_ONLY\" = 1; then\n"+
           "p208/P208StartCoroutineWitness.java\n"
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
        self.assertEqual(v.replace(p.AFTER,p.BEFORE,1),builder())
    def test_wrong_builder(self):
        self.deny("PINNED_P208_BUILDER_REQUIRED",lambda:p.patch_builder("untrusted"))
    def test_duplicate_source(self):
        self.deny("PINNED_P208_BUILDER_REQUIRED",lambda:p.patch_builder(builder()+p.BEFORE))
    def test_no_process_spawn(self):
        self.assertNotIn("ProcessBuilder.start",p.ENTER+p.STACK+p.FINAL)
if __name__=="__main__":unittest.main(verbosity=2)
