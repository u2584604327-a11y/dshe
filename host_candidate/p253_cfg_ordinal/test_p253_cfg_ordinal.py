#!/usr/bin/env python3
"""P253 30 synthetic fail-closed instruction, branch and try-edge fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics","host_candidate/p249_dual_diff",
              "host_candidate/p251_method_relation"]
from test_p246_exception_semantics import Code,Table,Handler,Try,Pair,Dex
from p246_exception_semantics import Deny
from p249_dual_diff import START
from p253_cfg_ordinal import compare_pair,audit_indexes,emit,branches,instructions

D=Dex()
OTHER=("Laaa/Synthetic;","test","()V")
NAMES=["const/4","goto","add-int","return-void","move-exception","return-void"]
class Op:
    def __init__(self,name,width=2,off=0):
        self.name,self.width,self.off=name,width,off
    def get_name(self):return self.name
    def get_length(self):return self.width
    def get_ref_off(self):return self.off
class NoRef(Op):
    def __getattribute__(self,k):
        if k=="get_ref_off":raise AttributeError(k)
        return super().__getattribute__(k)
class Method:
    def __init__(self,ops=None,tries=None,handler=4):
        self.ops=ops if ops is not None else [Op(n,2,3 if i==1 else 0)
                                              for i,n in enumerate(NAMES)]
        self.total=sum(x.get_length() for x in self.ops)//2
        ex=[Try(start=0,width=1)] if tries is None else tries
        table=Table([Handler(pairs=[Pair(3,handler)])]) if ex else Table([])
        self.code=Code(tries=ex,table=table,total=self.total)
    def get_code(self):return self.code
    def get_instructions_idx(self):
        pc=0
        result=[]
        for ins in self.ops:
            result.append((pc,ins))
            pc+=ins.get_length()
        return result
def base():return Method()
def width():
    ops=[Op(n,4 if i==2 else 2,4 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    return Method(ops,handler=5)
def wrong_jump():
    ops=[Op(n,4 if i==2 else 2,3 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    return Method(ops,handler=5)
def wrong_handler():
    ops=[Op(n,4 if i==2 else 2,4 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    return Method(ops,handler=4)
def added():
    ops=[Op(n,2,4 if i==1 else 0) for i,n in enumerate(NAMES)]
    ops.insert(3,Op("nop"))
    return Method(ops,handler=5)
def different_opcode():
    ops=[Op("const/16" if i==0 else n,2,3 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    return Method(ops)
def compare(a=None,b=None):
    return compare_pair(base() if a is None else a,
                        width() if b is None else b,D,D)
def audit(a=None,b=None,key=START):
    return audit_indexes({key:base() if a is None else a},
                         {key:width() if b is None else b},D,D)

class Tests(unittest.TestCase):
 def test_01_width_only_and_branch_ordinal(self):
    q=compare()
    self.assertEqual((q["layout"],q["branches"],q["exception"]),
                     ("WIDTH_ONLY","ORDINALS_MATCH_ONLY","ORDINALS_MATCH_ONLY"))
 def test_02_width_change_remains_size_deny(self):
    self.assertTrue(compare()["code_size_changed"])
 def test_03_same_layout(self):
    q=compare(base(),base())
    self.assertEqual((q["layout"],q["code_size_changed"]),("SAME_LAYOUT",False))
 def test_04_added_instruction(self):
    self.assertEqual(compare(base(),added())["layout"],"COUNT_CHANGED")
 def test_05_added_instruction_branch_changed(self):
    self.assertEqual(compare(base(),added())["branches"],"ORDINALS_DIFFER")
 def test_06_added_instruction_exception_changed(self):
    self.assertEqual(compare(base(),added())["exception"],"ORDINALS_DIFFER")
 def test_07_opcode_changed(self):
    self.assertEqual(compare(base(),different_opcode())["layout"],"OPCODE_CHANGED")
 def test_08_opcode_change_does_not_claim_cfg(self):
    self.assertEqual(compare(base(),different_opcode())["branches"],"ORDINALS_DIFFER")
 def test_09_branch_target_mismatch(self):
    self.assertEqual(compare(base(),wrong_jump())["branches"],"ORDINALS_DIFFER")
 def test_10_handler_target_ordinal_mismatch(self):
    self.assertEqual(compare(base(),wrong_handler())["exception"],"ORDINALS_DIFFER")
 def test_11_handler_ordinal_change_with_matching_normal(self):
    q=compare(base(),wrong_handler())
    self.assertEqual((q["branches"],q["exception"]),
                     ("ORDINALS_MATCH_ONLY","ORDINALS_DIFFER"))
 def test_12_first_size_target_group(self):
    self.assertEqual(audit()["group"],"START_COROUTINE")
 def test_13_first_size_other_group(self):
    self.assertEqual(audit(key=OTHER)["group"],"OTHER_PRIMARY")
 def test_14_first_size_and_exception_same_method(self):
    self.assertEqual(audit()["relation"],"SAME_METHOD")
 def test_15_no_code_size_change(self):
    q=audit(base(),base())
    self.assertEqual((q["group"],q["layout"]),("NONE","NONE"))
 def test_16_all_public_statuses_are_enumerations(self):
    q=audit()
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(q),2)
    self.assertNotIn(OTHER[0],buf.getvalue())
    self.assertNotIn(START[0],buf.getvalue())
    self.assertIn("P253_LEGAL_RELOCATION=NOT_ATTESTED",buf.getvalue())
    self.assertIn("P253_NORMAL_OPERANDS_AND_PAYLOADS=NOT_ATTESTED",buf.getvalue())
 def test_17_even_parity_no_release(self):
    q=audit(base(),base())
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(q),0)
    self.assertIn("P253_ORIGINAL_P245_FULL_STATIC=NOT_ATTESTED",buf.getvalue())
    self.assertIn("P253_V139=STRUCTURAL_BLOCKED",buf.getvalue())
 def test_18_branch_middle_of_instruction_denied(self):
    # Branch at byte PC 2 has code-unit PC 1. Offset 2 lands at PC 3,
    # which is the middle of the widened third instruction.
    ops=[Op(n,4 if i==2 else 2,2 if i==1 else 0)
         for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops,handler=5))
 def test_19_branch_out_of_bounds_denied(self):
    ops=[Op(n,2,999 if i==1 else 0) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_20_missing_branch_ref_denied(self):
    ops=[NoRef(n) if i==1 else Op(n) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_21_non_integer_branch_ref_denied(self):
    ops=[Op(n,2,"3" if i==1 else 0) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_22_switch_payload_requires_separate_audit(self):
    ops=[Op("packed-switch" if i==1 else n,2) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_23_switch_payload_record_denied(self):
    ops=[Op("packed-switch-payload" if i==1 else n,2) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_24_fill_array_data_denied(self):
    ops=[Op("fill-array-data" if i==1 else n,2) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_25_invalid_opcode_denied(self):
    ops=[Op("??" if i==0 else n,2,3 if i==1 else 0) for i,n in enumerate(NAMES)]
    with self.assertRaises(Deny):compare(base(),Method(ops))
 def test_26_truncated_decode_denied(self):
    x=base();x.code.total+=1
    with self.assertRaises(Deny):compare(base(),x)
 def test_27_try_boundary_misaligned_denied(self):
    y=width();y.code.tries=[Try(start=0,width=3)]
    with self.assertRaises(Deny):compare(base(),y)
 def test_28_handler_off_bad_denied(self):
    y=width();y.code.tries=[Try(start=0,width=1,off=99)]
    with self.assertRaises(Deny):compare(base(),y)
 def test_29_unapproved_method_set_denied(self):
    with self.assertRaises(Deny):
        audit_indexes({START:base()},{START:width(),OTHER:base()},D,D)
 def test_30_malformed_public_result_denied(self):
    q=audit();q["branches"]="PROVEN_SAFE"
    with self.assertRaises(Deny):emit(q)
if __name__=="__main__":unittest.main()
