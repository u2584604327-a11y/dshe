#!/usr/bin/env python3
"""P220 synthetic binary traces, not an original app or user-data sample."""
import struct,unittest
from p220_trace_parser import InvalidTrace,parse,classify,trace_size_band,MAX_BYTES
def sample(version=3,mid=0x100,cls="com.dsh.android.EngineManager$start$2",method="invokeSuspend",actions=(0,)):
 size={1:9,2:10,3:14}.get(version,14)
 head=(f"*version\n3\nclock=dual\n*threads\n1\tmain\n*methods\n"
       f"0x{mid:x}\t{cls}\t{method}\t()V\tS.java\t0\n*end\n").encode()
 body=(b"SLOW"+struct.pack("<HHQH",version,32,123,size)).ljust(32,b"\0")
 for action in actions:
  reg=b"\x01" if version==1 else b"\x01\x00"
  body+=reg+struct.pack("<I",mid|action)+b"\0"*(size-len(reg)-4)
 return head+body
class Tests(unittest.TestCase):
 def test_v1(self):self.assertEqual(parse(sample(version=1))[2]["START2"],1)
 def test_v2(self):self.assertEqual(parse(sample(version=2))[2]["START2"],1)
 def test_v3(self):self.assertEqual(parse(sample())[2]["START2"],1)
 def test_exit_not_entry(self):self.assertEqual(parse(sample(actions=(1,)))[2]["START2"],0)
 def test_unroll_not_entry(self):self.assertEqual(parse(sample(actions=(2,)))[2]["START2"],0)
 def test_install_node(self):
  self.assertEqual(parse(sample(cls="com.dsh.android.termux.TermuxBootstrap",method="installNodeRuntime"))[2]["NODE_INSTALL"],1)
 def test_wrong_class(self):self.assertEqual(parse(sample(cls="com.other.Thing"))[2]["START2"],0)
 def test_wrong_method(self):self.assertEqual(parse(sample(method="invoke"))[2]["START2"],0)
 def test_bad_magic(self):
  with self.assertRaises(InvalidTrace):parse(sample().replace(b"SLOW",b"FAIL",1))
 def test_bad_version(self):
  with self.assertRaises(InvalidTrace):parse(sample(version=4))
 def test_bad_key(self):
  with self.assertRaises(InvalidTrace):parse(sample().replace(b"0x100\t",b"broken\t",1))
 def test_no_method_section(self):
  with self.assertRaises(InvalidTrace):parse(sample().replace(b"*methods\n",b"*unknown\n"))
 def test_unaligned_id(self):
  with self.assertRaises(InvalidTrace):parse(sample(mid=0x101))
 def test_incomplete_record(self):
  with self.assertRaises(InvalidTrace):parse(sample()+b"x")
 def test_oversize(self):
  with self.assertRaises(InvalidTrace):parse(sample()+b"x"*(16*1024*1024))
 def test_duplicate_known_key(self):
  raw=sample();start=raw.index(b"0x100\t");line=raw[start:raw.index(b"\n",start)+1]
  with self.assertRaises(InvalidTrace):parse(raw.replace(line,line+line,1))
 def test_crlf_trace_header(self):
  raw=sample();prefix,bin=raw.split(b"SLOW",1)
  self.assertEqual(parse(prefix.replace(b"\n",b"\r\n")+b"SLOW"+bin)[2]["START2"],1)
 def test_64bit_key_does_not_alias_32bit(self):
  raw=sample(mid=0x100)
  self.assertEqual(parse(raw.replace(b"0x100\t",b"0x100000100\t"))[2]["START2"],0)
 def test_malformed_stage_label(self):
  with self.assertRaises(InvalidTrace) as e:
   parse(sample().replace(b"SLOW",b"FAIL",1))
  self.assertEqual(str(e.exception),"BINARY_MAGIC_OR_EMPTY")
 def test_size_band_empty(self):self.assertEqual(trace_size_band(0),"EMPTY")
 def test_size_band_tiny(self):self.assertEqual(trace_size_band(31),"TINY")
 def test_size_band_min(self):self.assertEqual(trace_size_band(32),"WITHIN_CAP")
 def test_size_band_max(self):self.assertEqual(trace_size_band(MAX_BYTES),"WITHIN_CAP")
 def test_size_band_over(self):self.assertEqual(trace_size_band(MAX_BYTES+1),"ABOVE_CAP")
 def test_dex_class_name(self):
  self.assertEqual(classify("Lcom/dsh/android/EngineManager$start$2;","invokeSuspend"),"START2")
if __name__=="__main__":unittest.main(verbosity=2)
