#!/usr/bin/env python3
"""P243 12 synthetic handler offset, CFG and fail-closed negative fixtures."""
import unittest
from p238_signed_coroutine_capture import Denied
from p243_signed_exception_handler_cfg import (
    exception_edges,any_handler_reaches_target
)
ROWS={0:("nop",""),2:("nop",""),4:("move-exception","v1"),
      6:("return-void",""),190:("iget-object","v3,v1,Lx;->a Ly;")}

class Tests(unittest.TestCase):
    def test_handler_directly_reaches_pc190(self):
        normal={0:(2,),2:(6,),4:(190,),6:(),190:()}
        exc,targets=exception_edges(ROWS,[(0,1,1)],{1:(2,)},100)
        self.assertEqual(any_handler_reaches_target(normal,exc,targets),"NO")
        exc,targets=exception_edges(ROWS,[(0,1,1)],{1:(2,)},100)
        self.assertEqual(any_handler_reaches_target(
            {0:(2,),2:(190,),4:(),6:(),190:()},exc,targets),"YES")

    def test_handler_no_back_edge(self):
        normal={0:(2,),2:(6,),4:(6,),6:(),190:()}
        exc,targets=exception_edges(ROWS,[(0,1,1)],{1:(2,)},100)
        self.assertEqual(any_handler_reaches_target(normal,exc,targets),"NO")

    def test_handler_chain_exception_edge_to_target(self):
        rows={0:("nop",""),2:("nop",""),4:("nop",""),
              6:("move-exception","v0"),8:("move-exception","v0"),
              190:("nop","")}
        normal={0:(2,),2:(4,),4:(6,),6:(),8:(190,),190:()}
        # handler entry pc6 can throw via a second try and transfer to pc8.
        exc,roots=exception_edges(rows,[(0,1,1),(3,1,2)],
                                  {1:(3,),2:(4,)},100)
        self.assertEqual(any_handler_reaches_target(normal,exc,roots),"YES")

    def test_byte_vs_codeunit_conversion(self):
        exc,roots=exception_edges(ROWS,[(0,1,1)],{1:(2,)},100)
        self.assertIn(4,roots)
        self.assertNotIn(2,roots)
        self.assertEqual(exc[0],(4,))

    def test_catch_all_and_typed_multiple_targets(self):
        exc,roots=exception_edges(ROWS,[(0,1,1)],{1:(1,2)},100)
        self.assertEqual(roots,frozenset({2,4}))
        self.assertEqual(exc[0],(2,4))

    def test_missing_handler_offset_denied(self):
        with self.assertRaises(Denied):
            exception_edges(ROWS,[(0,1,9)],{1:(2,)},100)

    def test_noninstruction_handler_target_denied(self):
        with self.assertRaises(Denied):
            exception_edges(ROWS,[(0,1,1)],{1:(5,)},100)

    def test_noninstruction_try_start_denied(self):
        with self.assertRaises(Denied):
            exception_edges(ROWS,[(1,1,1)],{1:(2,)},100)

    def test_overlapping_protected_ranges_denied(self):
        rows={**ROWS,10:("nop",""),12:("nop","")}
        with self.assertRaises(Denied):
            exception_edges(rows,[(0,3,1),(2,2,1)],{1:(2,)},100)

    def test_bad_handler_offset_type_denied(self):
        with self.assertRaises(Denied):
            exception_edges(ROWS,[(0,1,"1")],{1:(2,)},100)

    def test_unknown_successor_denied(self):
        with self.assertRaises(Denied):
            any_handler_reaches_target(
                {0:(888,),2:(),4:(),6:(),190:()},
                {0:(),2:(),4:(),6:(),190:()},frozenset({4}))

    def test_missing_target_denied(self):
        with self.assertRaises(Denied):
            any_handler_reaches_target(
                {0:(2,),2:(),4:(),6:()},
                {0:(),2:(),4:(),6:()},frozenset({4}))

if __name__=="__main__":
    unittest.main(verbosity=2)
