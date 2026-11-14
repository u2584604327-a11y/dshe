#!/usr/bin/env python3
"""P287 negative-only independent P245 gate delta proposal tests, no gate change."""
import contextlib,io,sys,unittest
from unittest.mock import patch
sys.path[:0]=[
 "host_candidate/p287_gate_delta",
 "host_candidate/p285_shadow_verifier",
 "host_candidate/p283_descriptor_normalization",
 "host_candidate/p281_helper_predicates",
 "host_candidate/p269_method_pool",
 "host_candidate/p267_invoke_words",
 "host_candidate/p249_dual_diff",
 "host_candidate/p246_exception_semantics",
]
import p287_gate_delta as m
from p246_exception_semantics import Deny
from p281_helper_predicates import PREDICATES
from p283_descriptor_normalization import DETAIL
from p285_shadow_verifier import FACTORS

TEXT="v1, v2, Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
def getter():
 return {x:"PASS" for x in DETAIL}
def logger():
 d={x:"PASS" for x in DETAIL}
 for x in ("RAW_ARGS_EXACT","OUTPUT_TEXT_EXACT"):d[x]="FAIL"
 return d
def oldpred():
 return {x:("FAIL" if x==PREDICATES[4] else "PASS") for x in PREDICATES}
def shadow():
 return {x:"PASS" for x in FACTORS}
def check(o=None,c=None,g=None,l=None,sh=None,text=None):
 return m.candidate(oldpred() if o is None else o,
  "ONE_TYPED_THROWABLE_MOVE_EXCEPTION" if c is None else c,
  getter() if g is None else g,logger() if l is None else l,
  shadow() if sh is None else sh,TEXT if text is None else text)
def verdict(**kwargs):
 return check(**kwargs)[1]
GOOD="SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE"
DENY="DENY_DIFFERENT_OR_UNVERIFIED"
class Tests(unittest.TestCase):
 def test_01_exact_inter_type_space(self):
  self.assertEqual(m.display_shape(TEXT),"PASS")
 def test_02_exact_inter_type_tab(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";\tLjava")),"PASS")
 def test_03_two_ascii_spaces(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";  Ljava")),"PASS")
 def test_04_mixed_ascii_space_tab(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava","; \tLjava")),"PASS")
 def test_05_no_separator_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";Ljava")),"FAIL")
 def test_06_leading_output_space_denied(self):
  self.assertEqual(m.display_shape(" "+TEXT),"FAIL")
 def test_07_trailing_output_space_denied(self):
  self.assertEqual(m.display_shape(TEXT+" "),"FAIL")
 def test_08_newline_separator_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";\nLjava")),"FAIL")
 def test_09_unicode_space_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";\u2009Ljava")),"FAIL")
 def test_10_comma_between_types_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("; Ljava",";,Ljava")),"FAIL")
 def test_11_inside_type_space_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("lang/String","lang/Str ing")),"FAIL")
 def test_12_owner_changed_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("android/util/Log","android/util/Logs")),"FAIL")
 def test_13_method_changed_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("->i(","->w(")),"FAIL")
 def test_14_return_changed_denied(self):
  self.assertEqual(m.display_shape(TEXT[:-1]+"V"),"FAIL")
 def test_15_one_arg_changed_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("Ljava/lang/String; Ljava/lang/String;",
                                               "Ljava/lang/String; Ljava/lang/Object;")),"FAIL")
 def test_16_operands_text_changed_denied(self):
  self.assertEqual(m.display_shape(TEXT.replace("v1, v2,","v2, v1,")),"FAIL")
 def test_17_duplicated_invocation_text_denied(self):
  self.assertEqual(m.display_shape(TEXT+TEXT),"FAIL")
 def test_18_malformed_or_unbounded_denied(self):
  self.assertEqual(m.display_shape("x"*9000),"UNVERIFIED")
 def test_19_non_string_denied(self):
  self.assertEqual(m.display_shape(None),"UNVERIFIED")
 def test_20_positive_gate_delta_is_draft_only(self):
  self.assertEqual(verdict(),GOOD)
 def test_21_first_original_try_predicate_false(self):
  o=oldpred();o[PREDICATES[0]]="FAIL"
  self.assertEqual(verdict(o=o),DENY)
 def test_22_original_iget_predicate_false(self):
  o=oldpred();o[PREDICATES[1]]="FAIL"
  self.assertEqual(verdict(o=o),DENY)
 def test_23_original_invoke_count_false(self):
  o=oldpred();o[PREDICATES[2]]="FAIL"
  self.assertEqual(verdict(o=o),DENY)
 def test_24_original_getter_text_false(self):
  o=oldpred();o[PREDICATES[3]]="FAIL"
  self.assertEqual(verdict(o=o),DENY)
 def test_25_original_log_text_pass_does_not_claim_delta(self):
  o=oldpred();o[PREDICATES[4]]="PASS"
  self.assertEqual(verdict(o=o),DENY)
 def test_26_original_unknown_fails_closed(self):
  o=oldpred();o[PREDICATES[1]]="UNVERIFIED"
  self.assertEqual(verdict(o=o),DENY)
 def test_27_original_missing_predicate_denied(self):
  o=oldpred();o.pop(PREDICATES[0])
  self.assertEqual(verdict(o=o),DENY)
 def test_28_typed_catch_changed(self):
  self.assertEqual(verdict(c="DIFFERENT"),DENY)
 def test_29_typed_catch_unverified(self):
  self.assertEqual(verdict(c="UNVERIFIED"),DENY)
 def test_30_getter_owner_mismatch(self):
  d=getter();d["RAW_OWNER"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_31_getter_signature_format_changed(self):
  d=getter();d["OUTPUT_TEXT_EXACT"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_32_getter_raw_unknown(self):
  d=getter();d["RAW_CANONICAL_TUPLE"]="UNVERIFIED"
  self.assertEqual(verdict(g=d),DENY)
 def test_33_log_word_registers_mismatch(self):
  d=logger();d["RAW_WORD_COUNT"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_34_log_raw_method_name_mismatch(self):
  d=logger();d["RAW_NAME"]="FAIL";d["RAW_CANONICAL_TUPLE"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_35_log_return_mismatch(self):
  d=logger();d["RAW_RETURN"]="FAIL";d["RAW_CANONICAL_TUPLE"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_36_log_param_canonical_invalid(self):
  d=logger();d["RAW_ARGS_CANONICAL"]="FAIL";d["RAW_CANONICAL_TUPLE"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_37_log_literal_exact_not_format_only(self):
  d=logger();d["RAW_ARGS_EXACT"]="PASS"
  self.assertEqual(verdict(l=d),DENY)
 def test_38_log_display_exact_not_format_only(self):
  d=logger();d["OUTPUT_TEXT_EXACT"]="PASS"
  self.assertEqual(verdict(l=d),DENY)
 def test_39_one_p285_factor_fails(self):
  d=shadow();d["CAPTURED_FIELD"]="FAIL"
  self.assertEqual(verdict(sh=d),DENY)
 def test_40_one_p285_factor_unknown(self):
  d=shadow();d["TYPED_TRY_CATCH"]="UNVERIFIED"
  self.assertEqual(verdict(sh=d),DENY)
 def test_41_missing_p285_factor(self):
  d=shadow();d.pop("METHOD_SET")
  self.assertEqual(verdict(sh=d),DENY)
 def test_42_tampered_display_denied_even_with_raw_valid(self):
  self.assertEqual(verdict(text=TEXT+" ;"),DENY)
 def test_43_approved_label_never_releases(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):
   self.assertEqual(m.emit(check()),2)
  v=out.getvalue()
  self.assertIn("P287_LOG_TEXT_REPLACEMENT_REVIEW="+GOOD,v)
  self.assertIn("P287_REPLACEMENT_APPROVAL=NOT_GRANTED",v)
  self.assertIn("P287_RELEASE=DENY",v)
 def test_44_public_forged_schema_denied(self):
  a,b=check();a["BYPASS"]="PASS"
  with self.assertRaises(Deny):m.emit((a,b))
 def test_45_forged_positive_label_denied(self):
  a,b=check(o={**oldpred(),PREDICATES[0]:"FAIL"})
  with self.assertRaises(Deny):m.emit((a,GOOD))
 def test_46_legacy_exact_unjustified_positive_denied(self):
  a,b=check()
  a["EXACT_ONE_ASCII_SEPARATOR"]="FAIL"
  with self.assertRaises(Deny):m.emit((a,GOOD))
 def test_47_integrated_audit_wires_expected_sources(self):
  base=object();derived=object();hm=object()
  row=(0,"invoke-static",6,None,TEXT)
  old={"base":hm};new={"base":hm,(m.OWNER,m.NAME,m.DESC):hm}
  fake_rows=[(0,"nop",2,None,"")]*10+[row]+[(0,"return-void",2,None,"")]*3
  observed={"rows":fake_rows,"predicates":{x:(x!=PREDICATES[4]) for x in PREDICATES}}
  ref={"calls":{"GETTER":getter(),"LOG":logger()}}
  with patch.object(m,"index",side_effect=[old,new]),\
       patch.object(m,"p245_checks",return_value=observed),\
       patch.object(m,"catch_profile",return_value="ONE_TYPED_THROWABLE_MOVE_EXCEPTION"),\
       patch.object(m,"p283_audit",return_value=ref),\
       patch.object(m,"p285_audit",return_value=shadow()):
   self.assertEqual(m.audit(base,derived)[1],GOOD)
 def test_48_wrong_method_set_integrated_denies(self):
  with patch.object(m,"index",side_effect=[{"base":object()},{"base":object()}]):
   self.assertEqual(m.audit(object(),object())[1],DENY)
 def test_49_source_only_no_real_claim(self):
  old=sys.argv;sys.argv=["p287"]
  try:
   out=io.StringIO()
   with contextlib.redirect_stdout(out):self.assertEqual(m.main(),0)
   self.assertIn("P287_REAL_DELTA_REVIEW=NOT_ATTESTED",out.getvalue())
  finally:sys.argv=old

 def test_50_spoof_getter_raw_word_count(self):
  d=getter();d["RAW_WORD_COUNT"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_51_spoof_getter_raw_name(self):
  d=getter();d["RAW_NAME"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_52_spoof_getter_return_type(self):
  d=getter();d["RAW_RETURN"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_53_spoof_getter_raw_args(self):
  d=getter();d["RAW_ARGS_EXACT"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_54_spoof_getter_raw_args_canonical(self):
  d=getter();d["RAW_ARGS_CANONICAL"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_55_spoof_getter_exact_output(self):
  d=getter();d["OUTPUT_TEXT_EXACT"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_56_spoof_getter_canonical_output(self):
  d=getter();d["OUTPUT_TEXT_CANONICAL"]="FAIL"
  self.assertEqual(verdict(g=d),DENY)
 def test_57_spoof_log_owner_despite_tuple_pass(self):
  d=logger();d["RAW_OWNER"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_58_spoof_log_name_despite_tuple_pass(self):
  d=logger();d["RAW_NAME"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_59_spoof_log_return_despite_tuple_pass(self):
  d=logger();d["RAW_RETURN"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_60_spoof_log_precomputed_canonical_flag(self):
  d=logger();d["RAW_CANONICAL_TUPLE"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_61_spoof_log_canonical_output_mismatch(self):
  d=logger();d["OUTPUT_TEXT_CANONICAL"]="FAIL"
  self.assertEqual(verdict(l=d),DENY)
 def test_62_spoof_unexpected_raw_status(self):
  d=getter();d["RAW_OWNER"]="ALLOW"
  self.assertEqual(verdict(g=d),DENY)
 def test_63_spoof_unknown_raw_status(self):
  d=logger();d["RAW_NAME"]="UNVERIFIED"
  self.assertEqual(verdict(l=d),DENY)
 def test_64_missing_log_raw_detail(self):
  d=logger();d.pop("RAW_OWNER")
  self.assertEqual(verdict(l=d),DENY)

if __name__=="__main__":unittest.main()
