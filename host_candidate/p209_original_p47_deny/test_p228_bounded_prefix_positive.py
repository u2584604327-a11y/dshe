#!/usr/bin/env python3
"""P228 synthetic bounded prefix coverage; no APK, account, or real trace."""
import unittest
from p228_bounded_prefix_positive import audit,align_prefix,PrefixInvalid,MAX_PREFIX
from test_p220_trace_parser import sample
from p220_trace_parser import InvalidTrace

class Tests(unittest.TestCase):
    def test_positive_start_entry(self):
        n,e,a=audit(sample(actions=(0,)))
        self.assertEqual((n,e["START2"]),(1,1))
    def test_exit_event_count(self):
        _,_,a=audit(sample(actions=(0,1)))
        self.assertEqual(a["START2"]["EXIT"],1)
    def test_unroll_event_count(self):
        _,_,a=audit(sample(actions=(0,2)))
        self.assertEqual(a["START2"]["UNROLL"],1)
    def test_node_entry_and_exit(self):
        _,e,a=audit(sample(cls="com.dsh.android.termux.TermuxBootstrap",
                           method="installNodeRuntime",actions=(0,1)))
        self.assertEqual((e["NODE_INSTALL"],a["NODE_INSTALL"]["EXIT"]),(1,1))
    def test_unrelated_not_attributed(self):
        _,e,_=audit(sample(cls="com.other.Service",actions=(0,)))
        self.assertEqual(e["NODE_INSTALL"],0)
    def test_last_partial_record_discarded(self):
        data=sample(actions=(0,1))+b"\xfe\x00\x01"
        self.assertEqual(audit(data)[0],2)
    def test_truncated_partial_record_does_not_create_exit(self):
        data=sample(actions=(0,1))
        cut=data[:-3]
        self.assertEqual(audit(cut)[2]["START2"]["EXIT"],0)
    def test_overlong_input_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(sample()+b"x"*(MAX_PREFIX+1))
    def test_missing_end_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(sample().replace(b"*end\n",b"*xx\n"))
    def test_bad_magic_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(sample().replace(b"SLOW",b"FAKE",1))
    def test_invalid_record_size_refused(self):
        raw=bytearray(sample())
        i=raw.index(b"SLOW")
        raw[i+16:i+18]=b"\xff\xff"
        with self.assertRaises(PrefixInvalid):
            align_prefix(bytes(raw))
    def test_bad_target_id_refused(self):
        raw=sample().replace(b"0x100\t",b"bad\t",1)
        with self.assertRaises(InvalidTrace):
            audit(raw)
    def test_unsupported_art_version_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(sample(version=2))
    def test_no_complete_record_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(sample(actions=())+b"\x00")
    def test_stream_without_valid_header_refused(self):
        with self.assertRaises(PrefixInvalid):
            align_prefix(b"X"*1024)

if __name__=="__main__":
    unittest.main(verbosity=2)
