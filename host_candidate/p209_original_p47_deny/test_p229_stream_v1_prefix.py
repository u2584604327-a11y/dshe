#!/usr/bin/env python3
"""Synthetic ART V1 streaming fixtures, 18 strict positive/negative tests."""
import struct
import unittest
from p229_stream_v1_prefix import inspect,Rejected,MAX_PREFIX

def trace(events=((1,4,0),),method="invokeSuspend",
          cls="com.dsh.android.EngineManager$start$2",ver=0xF3):
    head=(b"SLOW"+struct.pack("<HHQH",ver,32,1234,14)).ljust(32,b"\0")
    thread=b"\0\0\x02"+struct.pack("<HH",1,4)+b"main"
    info=(f"0x4\t{cls}\t{method}\t()V\tExample.kt\t1\n").encode()
    token=b"\0\0\x01"+struct.pack("<H",len(info))+info
    records=b"".join(struct.pack("<HI",tid,mid|action)+b"\0"*8
                     for tid,mid,action in events)
    return head+thread+token+records

class Tests(unittest.TestCase):
    def test_streaming_v3_header(self):
        self.assertEqual(inspect(trace())[0],1)
    def test_metadata_counts(self):
        self.assertEqual(inspect(trace())[1:3],(1,1))
    def test_start_entry(self):
        self.assertEqual(inspect(trace())[3]["START2"]["ENTER"],1)
    def test_node_enter_exit(self):
        a=inspect(trace(events=((1,4,0),(1,4,1)),cls="com.dsh.android.termux.TermuxBootstrap",
                        method="installNodeRuntime"))[3]["NODE_INSTALL"]
        self.assertEqual((a["ENTER"],a["EXIT"]),(1,1))
    def test_node_unroll(self):
        a=inspect(trace(events=((1,4,0),(1,4,2)),cls="com.dsh.android.termux.TermuxBootstrap",
                        method="installNodeRuntime"))[3]["NODE_INSTALL"]
        self.assertEqual(a["UNROLL"],1)
    def test_only_other_method_not_attributed(self):
        self.assertEqual(inspect(trace(cls="com.elsewhere.Other"))[3]["START2"]["ENTER"],0)
    def test_partial_final_event_skipped(self):
        a=inspect(trace(events=((1,4,0),(1,4,1)))[:-4])
        self.assertEqual(a[3]["START2"]["EXIT"],0)
        self.assertTrue(a[4])
    def test_header_magic_invalid(self):
        with self.assertRaises(Rejected):inspect(trace().replace(b"SLOW",b"FAIL",1))
    def test_stream_version_not_v3(self):
        with self.assertRaises(Rejected) as e:inspect(trace(ver=5))
        self.assertEqual(str(e.exception),"FORMAT_VERSION")
    def test_plain_nonstreaming_v3_rejected(self):
        with self.assertRaises(Rejected) as e:inspect(trace(ver=3))
        self.assertEqual(str(e.exception),"FORMAT_VERSION")
    def test_other_streaming_v2_rejected(self):
        with self.assertRaises(Rejected) as e:inspect(trace(ver=0xF2))
        self.assertEqual(str(e.exception),"FORMAT_VERSION")
    def test_newer_streaming_format_rejected(self):
        with self.assertRaises(Rejected) as e:inspect(trace(ver=0xF5))
        self.assertEqual(str(e.exception),"FORMAT_VERSION")
    def test_wrong_width_denied(self):
        raw=bytearray(trace());raw[16:18]=b"\x10\0"
        with self.assertRaises(Rejected):inspect(bytes(raw))
    def test_unknown_meta_denied(self):
        raw=trace().replace(b"\0\0\x02",b"\0\0\x07",1)
        with self.assertRaises(Rejected) as e:inspect(raw)
        self.assertEqual(str(e.exception),"UNKNOWN_META_TOKEN")
    def test_reserved_action_denied(self):
        with self.assertRaises(Rejected):inspect(trace(events=((1,4,3),)))
    def test_method_info_bad_id_denied(self):
        with self.assertRaises(Exception):inspect(trace().replace(b"0x4\t",b"BAD\t",1))
    def test_no_complete_event_denied(self):
        with self.assertRaises(Rejected):inspect(trace(events=()))
    def test_oversized_prefix_denied(self):
        with self.assertRaises(Rejected):inspect(trace()+b"X"*(MAX_PREFIX+1))

if __name__=="__main__":
    unittest.main(verbosity=2)
