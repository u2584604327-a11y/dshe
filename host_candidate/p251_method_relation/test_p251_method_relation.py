#!/usr/bin/env python3
"""P251 pure synthetic original-vs-derived DEX exception edge fixtures."""
import contextlib,io,sys,unittest
sys.path[:0]=["host_candidate/p246_exception_semantics","host_candidate/p249_dual_diff"]
from test_p246_exception_semantics import Method,Code,Dex,Try,Table,Handler,Pair,A
from p246_exception_semantics import Deny,decode
from p249_dual_diff import START
from p251_method_relation import classify,ordinal_edges,emit
D=Dex()
EARLY=("Laaa/Synthetic;","m","()V")
LATE=("Lzzz/Synthetic;","m","()V")
def base():return Method()
def size():return Method(code=Code(total=7),widths=[2,2,2,2,2,4])
def target():return Method(code=Code(table=Table([Handler(pairs=[Pair(3,4)])])))
def descriptor():return Method(code=Code(table=Table([Handler(pairs=[Pair(4,3)])])))
def moved():
    return Method(code=Code(total=7,tries=[Try(start=0,width=4)],
                       table=Table([Handler(pairs=[Pair(3,4)])])),
                  pcs=[0,2,6,8,10,12],widths=[2,4,2,2,2,2])
def wrong_ordinal():
    return Method(code=Code(total=7,tries=[Try(start=0,width=4)],
                       table=Table([Handler(pairs=[Pair(3,5)])])),
                  pcs=[0,2,6,8,10,12],widths=[2,4,2,2,2,2])
def changed_scope():
    return Method(code=Code(total=7,tries=[Try(start=0,width=5)],
                       table=Table([Handler(pairs=[Pair(3,4)])])),
                  pcs=[0,2,6,8,10,12],widths=[2,4,2,2,2,2])
def check(a=None,b=None):
    return classify({START:base()} if a is None else a,
                    {START:base()} if b is None else b,D,D)
class NoCode:
    def get_code(self):return None
class Tests(unittest.TestCase):
 def test_01_no_difference(self):
    self.assertEqual(check()["relation"],"NOT_APPLICABLE")
 def test_02_code_only(self):
    self.assertEqual(check({START:base()},{START:size()})["relation"],"NOT_APPLICABLE")
 def test_03_exception_only(self):
    self.assertEqual(check({START:base()},{START:target()})["relation"],"NOT_APPLICABLE")
 def test_04_both_same_method(self):
    self.assertEqual(check({START:base()},{START:moved()})["relation"],"SAME_METHOD")
 def test_05_both_other_same(self):
    self.assertEqual(check({EARLY:base()},{EARLY:moved()})["relation"],"SAME_METHOD")
 def test_06_both_other_but_different_methods(self):
    q=check({EARLY:base(),LATE:base()},{EARLY:size(),LATE:target()})
    self.assertEqual((q["size_group"],q["exception_group"],q["relation"]),
                     ("OTHER_PRIMARY","OTHER_PRIMARY","DIFFERENT_METHOD"))
 def test_07_start_code_other_exception(self):
    self.assertEqual(check({START:base(),LATE:base()},{START:size(),LATE:target()})["relation"],"DIFFERENT_METHOD")
 def test_08_other_code_start_exception(self):
    self.assertEqual(check({EARLY:base(),START:base()},{EARLY:size(),START:target()})["relation"],"DIFFERENT_METHOD")
 def test_09_sorted_first_method_is_consistent(self):
    self.assertEqual(check({EARLY:base(),LATE:base()},{EARLY:moved(),LATE:target()})["relation"],"SAME_METHOD")
 def test_10_true_ordinal_alignment_only(self):
    self.assertEqual(check({START:base()},{START:moved()})["alignment"],"ORDINALS_MATCH_ONLY")
 def test_11_wrong_target_ordinal_denied(self):
    self.assertEqual(check({START:base()},{START:wrong_ordinal()})["alignment"],"ORDINALS_DIFFER")
 def test_12_target_shift_without_size_rebase(self):
    self.assertEqual(check({START:base()},{START:target()})["alignment"],"ORDINALS_DIFFER")
 def test_13_changed_try_scope_must_not_pass(self):
    q=check({START:base()},{START:changed_scope()})
    self.assertEqual(q["exception_category"],"TRY_SPAN")
    self.assertEqual(q["alignment"],"NOT_APPLICABLE")
 def test_14_type_descriptor_not_target_ordinal(self):
    self.assertEqual(check({START:base()},{START:descriptor()})["alignment"],"NOT_APPLICABLE")
 def test_15_handler_order_not_target_ordinal(self):
    a=Method(code=Code(table=Table([Handler(size=2,pairs=[Pair(3,3),Pair(4,4)])])))
    b=Method(code=Code(table=Table([Handler(size=2,pairs=[Pair(4,4),Pair(3,3)])])))
    q=check({START:a},{START:b})
    self.assertEqual((q["exception_category"],q["alignment"]),("HANDLER_ORDER","NOT_APPLICABLE"))
 def test_16_bad_original_instruction_width(self):
    with self.assertRaises(Deny):check({START:Method(widths=[2,2,2,2,2,0])},{START:base()})
 def test_17_bad_derived_instruction_width(self):
    with self.assertRaises(Deny):check({START:base()},{START:Method(widths=[2,2,2,2,2,0])})
 def test_18_missing_original_method_denied(self):
    with self.assertRaises(Deny):check({START:base(),EARLY:base()},{START:base()})
 def test_19_extra_unapproved_method_denied(self):
    with self.assertRaises(Deny):check({START:base()},{START:base(),EARLY:base()})
 def test_20_no_code_all_methods_denied(self):
    with self.assertRaises(Deny):check({START:NoCode()},{START:NoCode()})
 def test_21_unbound_handler_denied(self):
    bad=Method(code=Code(table=Table([Handler(),Handler(off=102)])))
    with self.assertRaises(Deny):check({START:base()},{START:bad})
 def test_22_bad_target_boundary_denied(self):
    bad=Method(code=Code(table=Table([Handler(pairs=[Pair(3,7)])])))
    with self.assertRaises(Deny):check({START:base()},{START:bad})
 def test_23_invalid_try_to_handler_binding_denied(self):
    bad=Method(code=Code(tries=[Try(off=99)]))
    with self.assertRaises(Deny):check({START:base()},{START:bad})
 def test_24_byte_offset_relocation_no_semantics_change(self):
    changed=Method(code=Code(tries=[Try(off=4)],
                             table=Table([Handler(off=204)],total=6)))
    self.assertEqual(check({START:base()},{START:changed() if callable(changed) else changed})["relation"],"NOT_APPLICABLE")
 def test_25_exception_ordinal_map_preserved(self):
    self.assertEqual(ordinal_edges(base(),decode(base(),D)),ordinal_edges(moved(),decode(moved(),D)))
 def test_26_exception_ordinal_map_changed_on_scope_shift(self):
    self.assertNotEqual(ordinal_edges(base(),decode(base(),D)),ordinal_edges(changed_scope(),decode(changed_scope(),D)))
 def test_27_ordinal_target_bounds_denied(self):
    x=(6,((0,3,(((A,7),),None)),))
    with self.assertRaises(Deny):ordinal_edges(base(),x)
 def test_28_codesize_denied_even_ordinal_edges_match(self):
    q=check({START:base()},{START:moved()})
    self.assertEqual((q["code_gate"],q["exception_gate"]),("DENY","DENY"))
 def test_29_sanitized_report_and_no_art_certificate(self):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):
        self.assertEqual(emit(check({EARLY:base()},{EARLY:moved()})),2)
    msg=buf.getvalue()
    self.assertNotIn(EARLY[0],msg)
    self.assertNotIn(START[0],msg)
    self.assertNotIn(A,msg)
    self.assertIn("P251_LEGAL_RELOCATION=NOT_ATTESTED",msg)
    self.assertIn("P251_NORMAL_CFG_AND_OPERANDS=NOT_ATTESTED",msg)
 def test_30_parity_never_releases_app(self):
    buf=io.StringIO()
    with contextlib.redirect_stdout(buf):self.assertEqual(emit(check()),0)
    self.assertIn("P251_FULL_P245_GATE=NOT_ATTESTED",buf.getvalue())
    self.assertIn("P251_V139=STRUCTURAL_BLOCKED",buf.getvalue())
 def test_31_invalid_relation_report_denied(self):
    q=check();q["relation"]="SAME_METHOD"
    with self.assertRaises(Deny):emit(q)
 def test_32_invalid_alignment_report_denied(self):
    q=check();q["alignment"]="ORDINALS_MATCH_ONLY"
    with self.assertRaises(Deny):emit(q)
if __name__=="__main__":unittest.main()
