#!/usr/bin/env python3
"""P285 source-only strict independent DEX verification adversarial fixtures."""
import contextlib,io,sys,unittest
from unittest.mock import patch
sys.path[:0]=["host_candidate/p285_shadow_verifier","host_candidate/p283_descriptor_normalization",
             "host_candidate/p281_helper_predicates","host_candidate/p269_method_pool",
             "host_candidate/p267_invoke_words","host_candidate/p249_dual_diff",
             "host_candidate/p246_exception_semantics"]
import p285_shadow_verifier as m
from p246_exception_semantics import Deny

class Ins:
 def __init__(self,name,raw=b"",length=2,offset=None):
    self.name,self.raw,self.length,self.offset=name,raw,length,offset
 def get_name(self):return self.name
 def get_output(self):return ""
 def get_length(self):return self.length
 def get_raw(self):return self.raw
 def get_ref_off(self):
    if self.offset is None:raise ValueError("REF_UNVERIFIED")
    return self.offset

class Code:
 def __init__(self,regs=5,ins=1,outs=2):self.regs,self.ins,self.outs=regs,ins,outs
 def get_registers_size(self):return self.regs
 def get_ins_size(self):return self.ins
 def get_outs_size(self):return self.outs

class Method:
 def __init__(self,rows=None,code=None):
    self.rows=fresh_rows() if rows is None else rows
    self.code=Code() if code is None else code
 def get_instructions_idx(self):return list(self.rows)
 def get_code(self):return self.code

class Field:
 def __init__(self,name="this$0",owner=m.OWNER,typ=m.ENGINE):
    self.name,self.owner,self.typ=name,owner,typ
 def get_name(self):return self.name
 def get_class_name(self):return self.owner
 def get_descriptor(self):return self.typ

class Class:
 def __init__(self,fields=None):
    self.fields=[Field()] if fields is None else fields
 def get_name(self):return m.OWNER
 def get_fields(self):return self.fields

class Dex:
 def __init__(self,*,fields=None,ref=None,field=None,values=None):
    self.fields=fields if fields is not None else [Field()]
    self.ref=ref or {
     1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
     2:(m.LOG[0],m.LOG[1],("(Ljava/lang/String; Ljava/lang/String;)",m.LOG[3]))
    }
    self.field=field if field is not None else (m.OWNER,m.ENGINE,"this$0")
    self.values=values if values is not None else {7:"DSH",8:"true",9:"false"}
 def get_classes(self):return [Class(self.fields)]
 def get_cm_field(self,i):
    if i!=3:raise LookupError("PRIVATE")
    return self.field
 def get_cm_method(self,i):return self.ref[i]
 def get_cm_string(self,i):return self.values[i]

def refstring(idx,reg,jumbo=False):
    return bytes([0x1b if jumbo else 0x1a,reg])+idx.to_bytes(4 if jumbo else 2,"little")

def fresh_rows():
    x=[
    Ins("iget-object",bytes([0x54,0x40,3,0]),4),
    Ins("if-eqz",length=4,offset=13),
    Ins("invoke-static",bytes([0x71,0x10,1,0,0,0]),6),
    Ins("move-result-object",length=2),
    Ins("if-eqz",length=4,offset=7),
    Ins("const-string",refstring(7,1),4),
    Ins("const-string",refstring(8,2),4),
    Ins("goto",length=2,offset=5),
    Ins("const-string",refstring(7,1),4),
    Ins("const-string",refstring(9,2),4),
    Ins("invoke-static",bytes([0x71,0x20,2,0,0x21,0]),6),
    Ins("return-void"),
    Ins("move-exception"),
    Ins("return-void")
    ]
    rows=[];pc=0
    for op in x:
        rows.append((pc,op));pc+=op.length
    return rows

def change(row_idx,*,name=None,raw=None,length=None,off=None):
    a=fresh_rows()
    orig=a[row_idx][1]
    a[row_idx]=(a[row_idx][0],Ins(orig.name if name is None else name,
      orig.raw if raw is None else raw,orig.length if length is None else length,
      orig.offset if off is None else off))
    return Method(a)

def rows(method=None):
    return m.helper_rows(method if method is not None else Method())

def decoded(typ="Ljava/lang/Throwable;",start=0,end=22,target=23,
            catchall=None):
    return (25,((start,end-start,(((typ,target),),catchall)),))

def evaluate(method=None,dex=None):
    method=Method() if method is None else method
    dex=Dex() if dex is None else dex
    with patch.object(m,"decode",return_value=decoded()):
        return m.inspect_helper(method,dex,"this$0")

class Tests(unittest.TestCase):
 def test_01_sequence_valid(self):
    self.assertEqual(m.shape(rows()),"PASS")
 def test_02_frame_valid(self):
    self.assertEqual(m.frame(Method()),"PASS")
 def test_03_branch_valid(self):
    self.assertEqual(m.branches(rows()),"PASS")
 def test_04_field_valid(self):
    self.assertEqual(m.raw_field(rows()[0],Dex(),"this$0"),"PASS")
 def test_05_getter_valid(self):
    self.assertEqual(m.raw_static(rows()[2],Dex(),m.GETTER,(0,)),"PASS")
 def test_06_log_valid_with_space_between_types(self):
    self.assertEqual(m.raw_static(rows()[10],Dex(),m.LOG,(1,2)),"PASS")
 def test_07_literal_flow_valid(self):
    self.assertEqual(m.safe_literal_flow(rows(),Dex()),"PASS")
 def test_08_handler_valid(self):
    with patch.object(m,"decode",return_value=decoded()):
        self.assertEqual(m.try_catch(Method(),Dex(),rows()),"PASS")
 def test_09_all_local_predicates_pass(self):
    d=evaluate()
    self.assertTrue(all(d[k]=="PASS" for k in m.FACTORS[3:]))
 def test_10_wrong_outs_frame(self):
    self.assertEqual(m.frame(Method(code=Code(outs=1))),"FAIL")
 def test_11_wrong_ins_frame(self):
    self.assertEqual(m.frame(Method(code=Code(ins=0))),"FAIL")
 def test_12_wrong_register_frame(self):
    self.assertEqual(m.frame(Method(code=Code(regs=6))),"FAIL")
 def test_13_invalid_frame_type(self):
    self.assertEqual(m.frame(Method(code=Code(regs=True))),"UNVERIFIED")
 def test_14_wrong_field_opcode(self):
    a=change(0,raw=bytes([0x52,0x40,3,0]))
    self.assertEqual(m.raw_field(rows(a)[0],Dex(),"this$0"),"FAIL")
 def test_15_wrong_field_source_reg(self):
    a=change(0,raw=bytes([0x54,0x30,3,0]))
    self.assertEqual(m.raw_field(rows(a)[0],Dex(),"this$0"),"FAIL")
 def test_16_wrong_field_owner(self):
    self.assertEqual(m.raw_field(rows()[0],Dex(field=("Lwrong/Cls;",m.ENGINE,"this$0")),"this$0"),"FAIL")
 def test_17_wrong_field_type(self):
    self.assertEqual(m.raw_field(rows()[0],Dex(field=(m.OWNER,"Ljava/lang/Object;","this$0")),"this$0"),"FAIL")
 def test_18_wrong_capture_name(self):
    self.assertEqual(m.raw_field(rows()[0],Dex(),"notCaptured"),"FAIL")
 def test_19_missing_capture_not_attested(self):
    self.assertEqual(m.raw_field(rows()[0],Dex(),None),"UNVERIFIED")
 def test_20_malformed_field_index(self):
    a=change(0,raw=bytes([0x54,0x40,6,0]))
    self.assertEqual(m.raw_field(rows(a)[0],Dex(),"this$0"),"UNVERIFIED")
 def test_21_missing_getter_ref(self):
    a=change(2,raw=bytes([0x71,0x10,0xff,0,0,0]))
    self.assertEqual(m.raw_static(rows(a)[2],Dex(),m.GETTER,(0,)),"UNVERIFIED")
 def test_22_wrong_getter_words(self):
    a=change(2,raw=bytes([0x71,0x10,1,0,1,0]))
    self.assertEqual(m.raw_static(rows(a)[2],Dex(),m.GETTER,(0,)),"FAIL")
 def test_23_wrong_log_register_order(self):
    a=change(10,raw=bytes([0x71,0x20,2,0,0x12,0]))
    self.assertEqual(m.raw_static(rows(a)[10],Dex(),m.LOG,(1,2)),"FAIL")
 def test_24_wrong_log_owner(self):
    d=Dex(ref={1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
               2:("Landroid/Wrong;",m.LOG[1],(m.LOG[2],m.LOG[3]))})
    self.assertEqual(m.raw_static(rows()[10],d,m.LOG,(1,2)),"FAIL")
 def test_25_wrong_log_method_name(self):
    d=Dex(ref={1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
               2:(m.LOG[0],"w",(m.LOG[2],m.LOG[3]))})
    self.assertEqual(m.raw_static(rows()[10],d,m.LOG,(1,2)),"FAIL")
 def test_26_wrong_log_param_type(self):
    d=Dex(ref={1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
               2:(m.LOG[0],m.LOG[1],("(Ljava/lang/String;Ljava/lang/Object;)","I"))})
    self.assertEqual(m.raw_static(rows()[10],d,m.LOG,(1,2)),"FAIL")
 def test_27_wrong_log_return(self):
    d=Dex(ref={1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
               2:(m.LOG[0],m.LOG[1],(m.LOG[2],"V"))})
    self.assertEqual(m.raw_static(rows()[10],d,m.LOG,(1,2)),"FAIL")
 def test_28_invalid_descriptor_type_internal_space(self):
    d=Dex(ref={1:(m.GETTER[0],m.GETTER[1],(m.GETTER[2],m.GETTER[3])),
               2:(m.LOG[0],m.LOG[1],("(Ljava/lang/Str ing;Ljava/lang/String;)","I"))})
    self.assertEqual(m.raw_static(rows()[10],d,m.LOG,(1,2)),"UNVERIFIED")
 def test_29_invalid_raw_invoke_format(self):
    a=change(10,raw=b"foobar")
    self.assertEqual(m.raw_static(rows(a)[10],Dex(),m.LOG,(1,2)),"UNVERIFIED")
 def test_30_other_op_not_accepted(self):
    a=change(3,name="move-wide")
    self.assertEqual(m.shape(rows(a)),"FAIL")
 def test_31_extra_instruction_not_accepted(self):
    a=fresh_rows();a.append((50,Ins("nop")))
    self.assertEqual(m.shape(rows(Method(a))),"FAIL")
 def test_32_wrong_if_first_target(self):
    a=change(1,off=12)
    self.assertEqual(m.branches(rows(a)),"FAIL")
 def test_33_wrong_if_second_target(self):
    a=change(4,off=8)
    self.assertEqual(m.branches(rows(a)),"FAIL")
 def test_34_wrong_goto_target(self):
    a=change(7,off=4)
    self.assertEqual(m.branches(rows(a)),"FAIL")
 def test_35_missing_branch_ref_unverified(self):
    a=change(7,off=999)
    a.rows[7][1].offset=None
    self.assertEqual(m.branches(rows(a)),"UNVERIFIED")
 def test_36_wrong_literal_tag(self):
    d=Dex(values={7:"secret",8:"true",9:"false"})
    self.assertEqual(m.safe_literal_flow(rows(),d),"FAIL")
 def test_37_changed_literal_tag_in_second_branch(self):
    a=change(8,raw=refstring(8,1))
    self.assertEqual(m.safe_literal_flow(rows(a),Dex()),"FAIL")
 def test_38_false_state_swapped(self):
    a=change(9,raw=refstring(8,2))
    self.assertEqual(m.safe_literal_flow(rows(a),Dex()),"FAIL")
 def test_39_wrong_literal_register(self):
    a=change(6,raw=refstring(8,1))
    self.assertEqual(m.safe_literal_flow(rows(a),Dex()),"UNVERIFIED")
 def test_40_missing_literal_index(self):
    a=change(6,raw=refstring(11,2))
    self.assertEqual(m.safe_literal_flow(rows(a),Dex()),"UNVERIFIED")
 def test_41_jumbo_string_allowed_if_content_same(self):
    a=fresh_rows()
    a[5]=(a[5][0],Ins("const-string/jumbo",refstring(7,1,True),6))
    pc=0;rebuilt=[]
    for _,inst in a:
      rebuilt.append((pc,inst))
      pc+=inst.length
    self.assertEqual(m.shape(rows(Method(rebuilt))),"PASS")
    self.assertEqual(m.safe_literal_flow(rows(Method(rebuilt)),Dex()),"PASS")
 def test_42_wrong_catch_type(self):
    with patch.object(m,"decode",return_value=decoded(typ="Ljava/lang/Error;")):
      self.assertEqual(m.try_catch(Method(),Dex(),rows()),"FAIL")
 def test_43_catchall_not_accepted(self):
    with patch.object(m,"decode",return_value=decoded(catchall=23)):
      self.assertEqual(m.try_catch(Method(),Dex(),rows()),"FAIL")
 def test_44_wrong_try_end(self):
    with patch.object(m,"decode",return_value=decoded(end=21)):
      self.assertEqual(m.try_catch(Method(),Dex(),rows()),"FAIL")
 def test_45_wrong_handler_pc(self):
    with patch.object(m,"decode",return_value=decoded(target=24)):
      self.assertEqual(m.try_catch(Method(),Dex(),rows()),"FAIL")
 def test_46_capture_unique_from_baseline(self):
    self.assertEqual(m.capture_from_baseline(Dex()),"this$0")
 def test_47_duplicate_capture_rejected(self):
    d=Dex(fields=[Field(),Field(name="other")])
    self.assertIsNone(m.capture_from_baseline(d))
 def test_48_bad_capture_type_rejected(self):
    self.assertIsNone(m.capture_from_baseline(Dex(fields=[Field(typ="Ljava/lang/Object;")])))
 def test_49_emit_pass_shadow_still_denies_release(self):
    out=io.StringIO();d={x:"PASS" for x in m.FACTORS}
    with contextlib.redirect_stdout(out):
        self.assertEqual(m.emit(d),2)
    s=out.getvalue()
    self.assertIn("P285_SHADOW=STRICT_STRUCTURAL_CANDIDATE_ONLY",s)
    self.assertIn("P285_RELEASE=DENY",s)
    self.assertNotIn(m.ENGINE,s)
 def test_50_spoofed_factor_rejected(self):
    d={x:"PASS" for x in m.FACTORS};d["OVERRIDE"]= "PASS"
    with self.assertRaises(Deny):m.emit(d)
 def test_51_missing_method_set_cannot_claim_other_checks(self):
    d={x:"PASS" for x in m.FACTORS};d["METHOD_SET"]="FAIL"
    with self.assertRaises(Deny):m.emit(d)
 def test_52_source_only_never_claims_real(self):
    old=sys.argv;sys.argv=["p285"]
    try:
       out=io.StringIO()
       with contextlib.redirect_stdout(out):self.assertEqual(m.main(),0)
       self.assertIn("P285_REAL_SHADOW=NOT_ATTESTED",out.getvalue())
    finally:sys.argv=old

if __name__=="__main__":unittest.main()
