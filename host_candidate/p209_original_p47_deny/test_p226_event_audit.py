#!/usr/bin/env python3
"""P226 synthetic record actions; NEVER conflated with original Android runtime."""
import unittest
from p220_trace_parser import parse,InvalidTrace
from p226_event_audit import inspect
from test_p220_trace_parser import sample
class Cases(unittest.TestCase):
 def test_enter_exit_unroll(self):
  a=inspect(sample(actions=(0,1,2)))
  self.assertEqual(a[3]["START2"],{"ENTER":1,"EXIT":1,"UNROLL":1})
 def test_returned_old_api_three_elements(self):
  self.assertEqual(len(parse(sample())),3)
 def test_sole_enter(self):
  self.assertEqual(inspect(sample(actions=(0,)))[3]["START2"]["ENTER"],1)
 def test_sole_exit_not_entry(self):
  a=inspect(sample(actions=(1,)))
  self.assertEqual(a[2]["START2"],0)
  self.assertEqual(a[3]["START2"]["EXIT"],1)
 def test_unroll_not_normal_exit(self):
  a=inspect(sample(actions=(2,)))[3]["START2"]
  self.assertEqual((a["EXIT"],a["UNROLL"]),(0,1))
 def test_invalid_action_3_denied(self):
  with self.assertRaises(InvalidTrace) as e:inspect(sample(actions=(3,)))
  self.assertEqual(str(e.exception),"BINARY_ACTION_UNSUPPORTED")
 def test_only_unknown_class_no_whitelist(self):
  self.assertEqual(inspect(sample(cls="com.other.Test"))[3]["START2"]["ENTER"],0)
 def test_decimal_key_event_join(self):
  s=sample(actions=(0,1)).replace(b"0x100\t",b"256\t",1)
  self.assertEqual(inspect(s)[3]["START2"]["EXIT"],1)
 def test_v2_denied_by_strict_diagnostic(self):
  with self.assertRaises(InvalidTrace) as e:inspect(sample(version=2))
  self.assertEqual(str(e.exception),"P226_ART_V3_REQUIRED")
 def test_v1_denied_by_strict_diagnostic(self):
  with self.assertRaises(InvalidTrace):inspect(sample(version=1))
 def test_missing_records_denied(self):
  with self.assertRaises(InvalidTrace):inspect(sample(actions=()))
 def test_node_install_exit_class(self):
  s=sample(cls="com.dsh.android.termux.TermuxBootstrap",method="installNodeRuntime",actions=(0,1))
  self.assertEqual(inspect(s)[3]["NODE_INSTALL"]["EXIT"],1)
if __name__=="__main__":unittest.main(verbosity=2)
