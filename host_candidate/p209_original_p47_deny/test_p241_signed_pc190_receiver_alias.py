#!/usr/bin/env python3
"""P241 synthetic receiver-alias CFG positives and fail-closed negatives."""
import unittest
from p238_signed_coroutine_capture import Denied
from p241_signed_pc190_receiver_alias import normal_alias,ALIAS

def fake(rows,edges,receiver=0,source=1,target=6):
    return normal_alias(rows,edges,receiver,source,target)

class Tests(unittest.TestCase):
    def test_direct_copy_all_normal_paths(self):
        self.assertEqual(fake({0:("move-object","v1, v0"),6:("iget-object","v2, v1, Lx;->p Ly;")},
                              {0:(6,),6:()})[0],"ALL_NORMAL_PATHS")
    def test_receiver_copy_through_intermediate_register(self):
        self.assertEqual(fake({0:("move-object","v2, v0"),2:("move-object","v1, v2"),6:("iget-object","v3, v1, Lx;->p Ly;")},
                              {0:(2,),2:(6,),6:()})[0],"ALL_NORMAL_PATHS")
    def test_two_valid_branch_paths(self):
        self.assertEqual(fake({0:("if-ne","v0,v1,:test"),2:("move-object","v1,v0"),4:("move-object","v1,v0"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(2,4),2:(6,),4:(6,),6:()})[0],"ALL_NORMAL_PATHS")
    def test_one_branch_overwrites(self):
        self.assertEqual(fake({0:("if-ne","v0,v1,:test"),2:("move-object","v1,v0"),4:("const/4","v1,0"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(2,4),2:(6,),4:(6,),6:()})[0],"MIXED_NORMAL_PATHS")
    def test_overwritten_alias_not_attested(self):
        self.assertEqual(fake({0:("move-object","v1,v0"),2:("iget-object","v1,v3,Lx;->p Ly;"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(2,),2:(6,),6:()})[0],"NOT_ATTESTED")
    def test_unknown_initial_register(self):
        self.assertEqual(fake({0:("nop",""),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(6,),6:()})[0],"NOT_ATTESTED")
    def test_unrecognized_write_blocks_must(self):
        val=fake({0:("move-object","v1,v0"),2:("mystery","v2,v3"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                 {0:(2,),2:(6,),6:()})
        self.assertEqual(val[0],"NOT_ATTESTED")
        self.assertTrue(val[1])
    def test_unreachable_target_not_attested(self):
        self.assertEqual(fake({0:("return-void",""),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(),6:()})[0],"NOT_ATTESTED")
    def test_cycle_converges(self):
        self.assertEqual(fake({0:("move-object","v1,v0"),2:("if-ne","v0,v1,:test"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                              {0:(2,),2:(2,6),6:()})[0],"ALL_NORMAL_PATHS")
    def test_malformed_move_cannot_establish_alias(self):
        val=fake({0:("move-object","bad"),6:("iget-object","v3,v1,Lx;->p Ly;")},
                 {0:(6,),6:()})
        self.assertEqual(val[0],"NOT_ATTESTED")
        self.assertTrue(val[1])
    def test_invalid_edge_is_denied(self):
        with self.assertRaises(Denied):
            fake({0:("move-object","v1,v0"),6:("iget-object","v3,v1,Lx;->p Ly;")},{0:(8,),6:()})
    def test_reg_bound_denied(self):
        with self.assertRaises(Denied):
            fake({0:("nop",""),6:("nop","")},{0:(6,),6:()},source=1000)
if __name__=="__main__":
    unittest.main(verbosity=2)
