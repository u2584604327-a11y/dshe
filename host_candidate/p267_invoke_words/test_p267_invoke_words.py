#!/usr/bin/env python3
"""P267 31 negative/positive PRIVATE synthetic tests, no APK/device operation."""
import contextlib,io,sys,unittest
from unittest.mock import patch
sys.path.insert(0,"host_candidate/p267_invoke_words")
from p267_invoke_words import (FIXED,RANGE,CAUSES,raw_words,reference,
                               type_widths,wide_valid,classify,emit,main)
REF="Lx/Test;->call(JI)V"
class Instruction:
 def __init__(self,name,regs=(),index=17,ref=REF,raw=None,api=True,partial=False):
    self.name=name;self.regs=tuple(regs);self.index=index;self.ref=ref
    if raw is not None:self.raw=raw
    elif name in FIXED:
        rr=list(regs)+[0]*5
        self.raw=bytes((FIXED[name],(len(regs)<<4)|rr[4],
                        index&255,index>>8,rr[0]|(rr[1]<<4),rr[2]|(rr[3]<<4)))
    elif name in RANGE:
        if regs:
            assert tuple(regs)==tuple(range(regs[0],regs[0]+len(regs)))
        self.raw=bytes((RANGE[name],len(regs),index&255,index>>8,
                        regs[0]&255 if regs else 0,
                        regs[0]>>8 if regs else 0))
    else:self.raw=b""
    self.api=api;self.partial=partial
 def get_raw(self):return self.raw
 def get_operands(self):
    if not self.api:raise ValueError("PRIVATE_PASSWORD_SHOULD_NOT_LEAK")
    regs=self.regs
    if self.partial and self.name in RANGE and regs:regs=regs[:1]
    ans=[(0,r) for r in regs]
    if self.ref is not None:ans.append((260,self.index,self.ref))
    return ans
class Code:
 def __init__(self,registers=64,outs=12):self.r=registers;self.o=outs
 def get_registers_size(self):return self.r
 def get_ins_size(self):return 0
 def get_outs_size(self):return self.o
class Method:
 def __init__(self,registers=64,outs=12):self.c=Code(registers,outs)
 def get_code(self):return self.c
def row(name,regs,**kwargs):
 return (0,name,6,Instruction(name,regs,**kwargs))
def pair(kind="static",w=(1,2,3),w2=None,ref=REF,ref2=None,**kwargs):
 a="invoke-"+kind;b=a+"/range"
 return (row(a,w,ref=ref),row(b,w if w2 is None else w2,
             ref=ref if ref2 is None else ref2,**kwargs))
def result(a=None,b=None,ma=None,mb=None):
 if a is None:a,b=pair()
 return classify(a,b,ma or Method(),mb or Method())
class Tests(unittest.TestCase):
 def test_01_fixed_opcode_mapping(self):
    self.assertEqual((FIXED["invoke-virtual"],RANGE["invoke-virtual/range"]),(0x6e,0x74))
 def test_02_raw_fixed_register_words(self):
    a,_=pair();self.assertEqual(raw_words(a),((1,2,3),17))
 def test_03_raw_range_register_words(self):
    _,b=pair();self.assertEqual(raw_words(b),((1,2,3),17))
 def test_04_range_start_only_decoder_view(self):
    _,b=pair();b=row("invoke-static/range",(1,2,3),partial=True)
    self.assertEqual(reference(b,(1,2,3),17),(260,REF))
 def test_05_normalized_count_irrelevant(self):
    self.assertEqual(result(),"INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE")
 def test_06_changed_word_sequence(self):
    a,b=pair(w=(1,2,3),w2=(2,3,4))
    self.assertEqual(result(a,b),"INVOKE_WORD_SEQUENCE_CHANGED")
 def test_07_virtual_receiver_and_wide(self):
    ref="Lx/Test;->call(JI)V"
    a,b=pair("virtual",w=(0,1,2,3),ref=ref)
    self.assertEqual(result(a,b),"INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE")
 def test_08_virtual_receiver_word_mismatch(self):
    a,b=pair("virtual",w=(0,1,2,3),w2=(1,2,3,4))
    self.assertEqual(result(a,b),"INVOKE_WORD_SEQUENCE_CHANGED")
 def test_09_wrong_number_argument_words(self):
    a,b=pair(w=(1,2,3),w2=(1,2))
    self.assertEqual(result(a,b),"INVOKE_WORD_COUNT_CHANGED")
 def test_10_invalid_wide_pair(self):
    a=row("invoke-static",(1,3,4))
    b=row("invoke-static/range",(1,2,3))
    self.assertEqual(result(a,b),"INVOKE_WIDE_WORD_LAYOUT_INVALID")
 def test_11_raw_wrong_opcode(self):
    a,b=pair();b=row("invoke-static/range",(1,2,3),raw=b"\x77\x03\x11\x00\x01\x00")
    self.assertEqual(result(a,b),"INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE")
    b=row("invoke-static/range",(1,2,3),raw=b"\x76\x03\x11\x00\x01\x00")
    self.assertEqual(result(a,b),"INVOKE_RAW_FORMAT_UNATTESTED")
 def test_12_raw_truncated(self):
    a,b=pair();b=row("invoke-static/range",(1,2,3),raw=b"123")
    self.assertEqual(result(a,b),"INVOKE_RAW_FORMAT_UNATTESTED")
 def test_13_bad_frame(self):
    self.assertEqual(result(ma=Method(registers=2),mb=Method(registers=2)),"INVOKE_REGISTER_FRAME_INVALID")
 def test_14_outs_too_small(self):
    self.assertEqual(result(ma=Method(64,2),mb=Method(64,2)),"INVOKE_REGISTER_FRAME_INVALID")
 def test_15_different_frame(self):
    self.assertEqual(result(ma=Method(64,12),mb=Method(65,12)),"INVOKE_REGISTER_FRAME_INVALID")
 def test_16_reference_mismatch(self):
    a,b=pair(ref2="Lx/Test;->call(II)V")
    self.assertEqual(result(a,b),"INVOKE_METHOD_REFERENCE_CHANGED")
 def test_17_missing_ref(self):
    a,b=pair();b=row("invoke-static/range",(1,2,3),ref=None)
    self.assertEqual(result(a,b),"INVOKE_REFERENCE_NOT_ATTESTED")
 def test_18_unresolved_ref_exception(self):
    a,b=pair();b=row("invoke-static/range",(1,2,3),api=False)
    self.assertEqual(result(a,b),"INVOKE_REFERENCE_NOT_ATTESTED")
 def test_19_malformed_descriptor(self):
    a,b=pair(ref="not-resolved",ref2="not-resolved")
    self.assertEqual(result(a,b),"INVOKE_DESCRIPTOR_NOT_ATTESTED")
 def test_20_array_width_one(self):
    self.assertEqual(type_widths("Lx;->a([J[D)V",True),[1,1])
 def test_21_double_width_two(self):
    self.assertEqual(type_widths("Lx;->a(DJ)V",True),[2,2])
 def test_22_receiver_counts_one(self):
    self.assertEqual(type_widths("Lx;->a(JI)V",False),[1,2,1])
 def test_23_void_parameter_forbidden(self):
    self.assertIsNone(type_widths("Lx;->a(V)V",True))
 def test_24_return_proto_required(self):
    self.assertIsNone(type_widths("Lx;->a(I)",True))
 def test_25_invalid_object(self):
    self.assertIsNone(type_widths("Lx;->a(Lbad)V",True))
 def test_26_wide_validation(self):
    self.assertTrue(wide_valid((0,1,3),[2,1]))
    self.assertFalse(wide_valid((0,2,3),[2,1]))
 def test_27_non_invoke_encoding(self):
    a,b=pair();b=(0,"move/from16",4,b[3])
    self.assertEqual(result(a,b),"OTHER_ENCODING_FAMILY_NOT_ATTESTED")
 def test_28_reversed_pair(self):
    a,b=pair()
    self.assertEqual(result(b,a),"INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE")
 def test_29_fixed_partial_registers_unattested(self):
    a,b=pair();a[3].regs=(1,2)  # decoder view disagrees with raw 3 words
    self.assertEqual(result(a,b),"INVOKE_REFERENCE_NOT_ATTESTED")
 def test_30_public_denial_and_private_scrub(self):
    q={"causes":{k:0 for k in CAUSES},"examined":1,
       "unknown":492,"total_shapes":1}
    q["causes"]["INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE"]=1
    output=io.StringIO()
    with contextlib.redirect_stdout(output):self.assertEqual(emit(q),2)
    s=output.getvalue()
    self.assertIn("P267_RELEASE=DENY",s)
    self.assertNotIn("Lx/Test",s)
    self.assertNotIn("v1",s)
 def test_31_source_only_no_real_assertion(self):
    old=sys.argv
    try:
     sys.argv=["p267"]
     output=io.StringIO()
     with contextlib.redirect_stdout(output):self.assertEqual(main(),0)
     self.assertIn("P267_REAL_INVOKE_WORDS=NOT_ATTESTED",output.getvalue())
    finally:sys.argv=old
if __name__=="__main__":unittest.main()
