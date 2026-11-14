#!/usr/bin/env python3
"""P209 PC414 static CFG tests: positive/negative and lexical-only limits."""
import unittest
from audit_signed_pc414 import Denied,classify_guard,register_operands,lexical_writes

def fixture():
    by={
      250:{"op":"nop","length":2},
      414:{"op":"if-ne","length":4},
      418:{"op":"nop","length":2},
      430:{"op":"return-void","length":2},
      3912:{"op":"invoke-virtual","length":6},
    }
    return {250:(414,),414:(418,430),418:(3912,),430:(),3912:()},by

class GuardTest(unittest.TestCase):
    def test_signed_like_fall_reaches(self):
        edges,by=fixture()
        self.assertEqual(classify_guard(edges,by),
                         (418,430,True,False,False))
    def test_opposite_arm_is_not_assumed(self):
        edges,by=fixture()
        edges[418]=()
        edges[430]=(3912,)
        self.assertEqual(classify_guard(edges,by),
                         (418,430,False,True,False))
    def test_independent_bypass_is_reported(self):
        edges,by=fixture()
        edges[250]=(414,3912)
        self.assertEqual(classify_guard(edges,by),
                         (418,430,True,False,True))
    def test_branch_with_both_arms_reaching_refused(self):
        edges,by=fixture()
        edges[430]=(3912,)
        with self.assertRaises(Denied):
            classify_guard(edges,by)
    def test_malformed_opcode_refused(self):
        edges,by=fixture()
        by[414]["op"]="if-eq"
        with self.assertRaises(Denied):
            classify_guard(edges,by)
    def test_missing_or_wrong_guard_target_refused(self):
        edges,by=fixture()
        edges[414]=(418,)
        with self.assertRaises(Denied):
            classify_guard(edges,by)
    def test_register_parser(self):
        self.assertEqual(register_operands("v8, v7, +0034"),(8,7))
    def test_identical_registers_refused(self):
        with self.assertRaises(Denied):
            register_operands("v3, v3, +0034")
    def test_external_or_missing_operands_refused(self):
        for item in ("p1, v3, +0034","v1","v2, token, +0034"):
            with self.assertRaises(Denied):
                register_operands(item)
    def test_lexical_provenance_not_reaching_definition(self):
        class SyntheticInstruction:
            def __init__(self,op,out):
                self.op,self.out=op,out
            def get_name(self):return self.op
            def get_output(self):return self.out
        rows=[
          (250,SyntheticInstruction("const/4","v7, 0x1")),
          (258,SyntheticInstruction("if-ne","v7, v8, +0050")),
          (270,SyntheticInstruction("move-result","v7")),
          (400,SyntheticInstruction("return-object","v7")),
        ]
        self.assertEqual(lexical_writes(rows,7),
                         [(250,"const/4"),(270,"move-result")])
        self.assertEqual(lexical_writes(rows,8),[])

if __name__=="__main__":unittest.main(verbosity=2)
