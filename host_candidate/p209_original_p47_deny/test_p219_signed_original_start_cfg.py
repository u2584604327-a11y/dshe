#!/usr/bin/env python3
"""P219 normal CFG synthetic negatives, not original Android measurements."""
import unittest
from audit_signed_node_bootstrap import Denied
from p219_signed_original_start_cfg import reach,summarize

def fixture():
    graph={172:(3912,),182:(186,),186:(190,406),190:(194,),194:(),
           406:(412,),412:(414,),414:(172,418),418:(),
           3912:(3918,),3918:()}
    nodes={i:{"op":"return-object" if i in (194,418,3918)
           else "if-ne" if i==414 else "if-eqz" if i==186
           else "invoke-virtual"} for i in graph}
    return graph,nodes

class P219Tests(unittest.TestCase):
    def test_pc406_reachable(self):
        e,n=fixture()
        self.assertTrue(summarize(e,n)["p182_reaches_406"])
    def test_early_return_bypasses_pc406(self):
        e,n=fixture()
        self.assertEqual(summarize(e,n)["early_returns"],[194])
    def test_excluding_target_refuses_reachability(self):
        e,_=fixture()
        self.assertFalse(reach(e,182,406,excluded=406))
    def test_split_guard_identified(self):
        e,n=fixture()
        self.assertEqual(summarize(e,n)["split_guards"],[186])
    def test_taken_reaches_spawn(self):
        e,n=fixture()
        self.assertTrue(summarize(e,n)["taken_reaches_3912"])
    def test_fall_terminates(self):
        e,n=fixture()
        self.assertFalse(summarize(e,n)["fall_reaches_3912"])
    def test_guard_opcode_drift_denied(self):
        e,n=fixture()
        n[414]["op"]="if-eq"
        with self.assertRaises(Denied):summarize(e,n)
    def test_guard_target_drift_denied(self):
        e,n=fixture()
        e[414]=(172,194)
        with self.assertRaises(Denied):summarize(e,n)
    def test_nonterminal_return_denied(self):
        e,n=fixture()
        e[418]=(3912,)
        with self.assertRaises(Denied):summarize(e,n)
    def test_missing_pc406_denied(self):
        e,n=fixture()
        del n[406]
        with self.assertRaises(Denied):summarize(e,n)
    def test_duplicate_branch_successor_denied(self):
        e,n=fixture()
        e[186]=(406,406)
        with self.assertRaises(Denied):summarize(e,n)
    def test_pc406_unreachable_reports_not_reached(self):
        e,n=fixture()
        e[186]=(190,194)
        self.assertFalse(summarize(e,n)["p182_reaches_406"])

if __name__=="__main__":unittest.main(verbosity=2)
