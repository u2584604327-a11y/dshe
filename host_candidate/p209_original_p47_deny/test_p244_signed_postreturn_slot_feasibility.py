#!/usr/bin/env python3
"""P244 synthetic fail-closed receiver/35c-to-3rc eligibility tests."""
import unittest
from p244_signed_postreturn_slot_feasibility import (
    Refused, may_write_receiver, receiver_unchanged, same_width_candidate
)

class SlotTests(unittest.TestCase):
    def test_high_receiver_register_range_encoding(self):
        self.assertTrue(same_width_candidate("invoke-static", 6, 500, 2,
            "ALL_MODELED_PREFIX_EDGES", "NO"))
    def test_reject_opcode(self):
        self.assertFalse(same_width_candidate("invoke-static/range", 6, 20, 1,
            "ALL_MODELED_PREFIX_EDGES", "NO"))
    def test_reject_widened_slot(self):
        self.assertFalse(same_width_candidate("invoke-static", 8, 20, 1,
            "ALL_MODELED_PREFIX_EDGES", "NO"))
    def test_reject_invalid_register(self):
        for reg in (-1, 65536, True):
            self.assertFalse(same_width_candidate("invoke-static", 6, reg, 1,
                "ALL_MODELED_PREFIX_EDGES", "NO"))
    def test_reject_outs_size(self):
        self.assertFalse(same_width_candidate("invoke-static", 6, 20, 0,
            "ALL_MODELED_PREFIX_EDGES", "NO"))
    def test_reject_unproven_receiver(self):
        self.assertFalse(same_width_candidate("invoke-static", 6, 20, 1,
            "NOT_ATTESTED", "NO"))
    def test_reject_exception_handler_back_edge(self):
        self.assertFalse(same_width_candidate("invoke-static", 6, 20, 1,
            "ALL_MODELED_PREFIX_EDGES", "YES"))
    def test_two_branches_preserve_receiver(self):
        rows={0:("move-object","v1, v0"),2:("if-eqz","v1, +x"),
              4:("nop",""),6:("invoke-static/range","v0"),
              12:("iget-object","v2, v0, x")}
        edges={0:(2,),2:(4,6),4:(6,),6:(12,),12:()}
        self.assertEqual(receiver_unchanged(rows,edges,0,12),
                         "ALL_MODELED_PREFIX_EDGES")
    def test_one_arm_clobbers_receiver(self):
        rows={0:("nop",""),2:("if-eqz","v1, x"),
              4:("move-object","v0, v1"),6:("invoke-static/range","v0"),
              12:("iget-object","v2,v0,x")}
        edges={0:(2,),2:(4,6),4:(6,),6:(12,),12:()}
        self.assertEqual(receiver_unchanged(rows,edges,0,12),
                         "NOT_ATTESTED")
    def test_unreachable_clobber_irrelevant(self):
        rows={0:("nop",""),2:("goto","+x"),
              4:("move-object","v0,v1"),12:("nop","")}
        edges={0:(2,),2:(12,),4:(12,),12:()}
        self.assertEqual(receiver_unchanged(rows,edges,0,12),
                         "ALL_MODELED_PREFIX_EDGES")
    def test_wide_move_second_word(self):
        self.assertTrue(may_write_receiver("move-wide","v3,v5",4))
        self.assertTrue(may_write_receiver("move-result-wide","v3",4))
        self.assertTrue(may_write_receiver("const-wide","v3, 0",4))
    def test_unknown_opcode_is_not_trusted(self):
        self.assertEqual(receiver_unchanged(
            {0:("unknown-vm-op",""),2:("nop","")},{0:(2,),2:()},0,2),
            "NOT_ATTESTED")
    def test_invalid_cfg_destination_denied(self):
        with self.assertRaises(Refused):
            receiver_unchanged(
                {0:("nop",""),2:("nop","")},{0:(3,),2:()},0,2)
    def test_missing_entry_to_target(self):
        self.assertEqual(receiver_unchanged(
            {0:("nop",""),2:("nop","")},{0:(),2:()},0,2),
            "NOT_ATTESTED")
    def test_unparseable_write_is_conservative(self):
        self.assertTrue(may_write_receiver("const","BAD_FORMAT",0))

if __name__ == "__main__":
    unittest.main()
