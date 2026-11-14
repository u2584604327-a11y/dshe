#!/usr/bin/env python3
"""Negative tests for P209 pure normal-CFG helpers; no APK or runtime access."""
import unittest
from audit_signed_process_prelaunch import (
    Denied,path_avoiding,split_guards)

class ControlFlowTests(unittest.TestCase):
    def test_mandatory_spawn_cannot_be_bypassed(self):
        edges={0:(2,),2:(4,),4:(6,),6:()}
        self.assertTrue(path_avoiding(edges,0,6))
        self.assertFalse(path_avoiding(edges,0,6,forbidden=4))
    def test_forged_direct_setter_edge_is_detected(self):
        edges={0:(2,6),2:(4,),4:(6,),6:()}
        self.assertTrue(path_avoiding(edges,0,6,forbidden=4))
    def test_entry_or_target_exclusion_fails_closed(self):
        edges={0:(2,),2:()}
        self.assertFalse(path_avoiding(edges,0,2,forbidden=0))
        self.assertFalse(path_avoiding(edges,0,2,forbidden=2))
    def test_normal_branch_split_is_not_runtime_observation(self):
        edges={0:(2,),2:(4,6),4:(10,),6:(8,),8:(),10:()}
        by_pc={p:{"op":"if-eqz" if p==2 else "nop"} for p in edges}
        self.assertEqual(split_guards(edges,by_pc,0,10),[(2,"if-eqz")])
    def test_malformed_conditional_has_no_valid_successors(self):
        with self.assertRaises(Denied):
            split_guards({0:(2,),2:(4,),4:()},
                {0:{"op":"nop"},2:{"op":"if-eqz"},4:{"op":"return"}},
                0,4)

if __name__=="__main__":unittest.main(verbosity=2)
