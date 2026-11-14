#!/usr/bin/env python3
"""P291 40 adversarial fixture tests: cloned gate remains narrower or DENY."""
import contextlib,io,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path[:0]=[
 "host_candidate/p291_candidate_gate",
 "host_candidate/p289_strict_gate_proposal",
 "host_candidate/p287_gate_delta",
 "host_candidate/p285_shadow_verifier",
 "host_candidate/p283_descriptor_normalization",
 "host_candidate/p281_helper_predicates",
 "host_candidate/p269_method_pool",
 "host_candidate/p267_invoke_words",
 "host_candidate/p249_dual_diff",
 "host_candidate/p246_exception_semantics",
]
import p291_candidate_gate as m
from p285_shadow_verifier import FACTORS

EXACT="v1, v2, "+m.LOG_TARGET
SPACED="v1, v2, Landroid/util/Log;->i(Ljava/lang/String; Ljava/lang/String;)I"
CALLS=("RAW_LOG_35C_FORMAT","RAW_LOG_35C_REGISTERS","RAW_LOG_DEX_OWNER",
       "RAW_LOG_DEX_METHOD","RAW_LOG_DEX_ARGS","RAW_LOG_DEX_RETURN")
def row(text=SPACED,op="invoke-static"):
 return (0,op,6,None,text)
def rows(text=SPACED,op="invoke-static"):
 x=[(0,"nop",2,None,"")]*14
 x[10]=row(text,op)
 return tuple(x)
def raw():
 return {x:"PASS" for x in CALLS}
def shadow():
 return {x:"PASS" for x in FACTORS}
def test_gate(method=None,methodrows=None,raw_result=None,shadow_result=None,
              exception=None):
 if method is None:method=object()
 if methodrows is None:methodrows=rows()
 if raw_result is None:raw_result=raw()
 if shadow_result is None:shadow_result=shadow()
 with patch.object(m,"helper_rows",return_value=methodrows),\
      patch.object(m,"raw_log_target",return_value=raw_result),\
      patch.object(m,"shadow_audit",return_value=shadow_result),\
      patch.object(m,"display_shape",return_value="PASS" if
        methodrows is not None and len(methodrows)==14 and
        methodrows[10][4]==SPACED else "FAIL"):
    if exception is not None:
      with patch.object(m,"raw_log_target",side_effect=exception):
       return m.p291_strict_log_call(method,object(),object())
    return m.p291_strict_log_call(method,object(),object())

class Cases(unittest.TestCase):
 def test_01_original_sha_matches_repository_blob(self):
  x=m.ORIGINAL.read_bytes()
  self.assertEqual(m.git_blob_sha(x),m.ORIGINAL_GIT_SHA)
 def test_02_candidate_reversible_source(self):
  old=m.ORIGINAL.read_bytes().decode()
  new=m.make_candidate(old.encode())
  self.assertEqual(new.replace(m.NEW_TEXT,m.OLD_TEXT).replace(m.IMPORT_ADD,""),old)
 def test_03_original_anchor_only_removed(self):
  s=m.make_candidate(m.ORIGINAL.read_bytes())
  self.assertEqual(s.count(m.OLD_TEXT),0)
  self.assertEqual(s.count(m.NEW_TEXT),1)
 def test_04_import_injection_exact_one(self):
  s=m.make_candidate(m.ORIGINAL.read_bytes())
  self.assertEqual(s.count(m.IMPORT_ADD),1)
 def test_05_existing_full_gate_preserved(self):
  s=m.make_candidate(m.ORIGINAL.read_bytes())
  for name in ("ORIGINAL_INSTRUCTION_COUNT","ORIGINAL_REGISTERS",
               "ORIGINAL_EXCEPTION_SEMANTICS","BRANCH_OPERANDS_TARGETS",
               "EXACT_ONE_REPLACEMENT","MANIFEST","THIRD_DEX",
               "HELPER_TYPED_READ_AND_CATCH","P245_STATIC_BUILD_ONLY=PASS"):
   self.assertIn(name,s)
 def test_06_source_one_byte_mutation_denied(self):
  data=m.ORIGINAL.read_bytes().replace(b"P245 disposable",b"P245 changed")
  with self.assertRaises(ValueError):m.make_candidate(data)
 def test_07_extra_log_occurrence_denied(self):
  data=m.ORIGINAL.read_bytes()+m.OLD_TEXT.encode()
  with self.assertRaises(ValueError):m.make_candidate(data)
 def test_08_wrong_encoding_denied(self):
  data=b"\xff"*10
  with self.assertRaises(ValueError):m.make_candidate(data)
 def test_09_nonbytes_sha_unknown(self):
  self.assertIsNone(m.git_blob_sha("not bytes"))
 def test_10_bad_hash_nonbytes_denied(self):
  with self.assertRaises(ValueError):m.make_candidate("x")
 def test_11_positive_exact_original_display(self):
  self.assertTrue(test_gate(methodrows=rows(EXACT)))
 def test_12_positive_proved_space_display(self):
  self.assertTrue(test_gate())
 def test_13_empty_method_not_trusted(self):
  self.assertFalse(test_gate(methodrows=None if False else ()))
 def test_14_wrong_helper_opcode(self):
  self.assertFalse(test_gate(methodrows=rows(op="invoke-direct")))
 def test_15_wrong_helper_instruction_count(self):
  self.assertFalse(test_gate(methodrows=rows()[:-1]))
 def test_16_wrong_api_owner(self):
  d=raw();d["RAW_LOG_DEX_OWNER"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_17_unknown_api_owner(self):
  d=raw();d["RAW_LOG_DEX_OWNER"]="UNVERIFIED"
  self.assertFalse(test_gate(raw_result=d))
 def test_18_wrong_method_name(self):
  d=raw();d["RAW_LOG_DEX_METHOD"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_19_wrong_proto(self):
  d=raw();d["RAW_LOG_DEX_ARGS"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_20_illegal_proto_unknown(self):
  d=raw();d["RAW_LOG_DEX_ARGS"]="UNVERIFIED"
  self.assertFalse(test_gate(raw_result=d))
 def test_21_wrong_return(self):
  d=raw();d["RAW_LOG_DEX_RETURN"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_22_wrong_register_selection(self):
  d=raw();d["RAW_LOG_35C_REGISTERS"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_23_wrong_invoke_format(self):
  d=raw();d["RAW_LOG_35C_FORMAT"]="FAIL"
  self.assertFalse(test_gate(raw_result=d))
 def test_24_missing_raw_result_key(self):
  d=raw();d.pop("RAW_LOG_DEX_OWNER")
  self.assertFalse(test_gate(raw_result=d))
 def test_25_extra_raw_result_key(self):
  d=raw();d["UNSAFE"]="PASS"
  self.assertFalse(test_gate(raw_result=d))
 def test_26_bad_raw_status(self):
  d=raw();d["RAW_LOG_DEX_METHOD"]="ALLOW"
  self.assertFalse(test_gate(raw_result=d))
 def test_27_wrong_method_set(self):
  d=shadow();d["METHOD_SET"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_28_wrong_byte_size(self):
  d=shadow();d["BASE_CODE_SIZE"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_29_wrong_exception_table(self):
  d=shadow();d["BASE_EXCEPTION"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_30_wrong_frame(self):
  d=shadow();d["FRAME"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_31_wrong_instruction_sequence(self):
  d=shadow();d["INSTRUCTION_SEQUENCE"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_32_wrong_branch_targets(self):
  d=shadow();d["BRANCH_TARGETS"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_33_wrong_captured_field(self):
  d=shadow();d["CAPTURED_FIELD"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_34_wrong_getter_id(self):
  d=shadow();d["GETTER_RAW_35C"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_35_wrong_literals(self):
  d=shadow();d["SAFE_LITERAL_FLOW"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_36_wrong_typed_handler(self):
  d=shadow();d["TYPED_TRY_CATCH"]="FAIL"
  self.assertFalse(test_gate(shadow_result=d))
 def test_37_missing_shadow_status(self):
  d=shadow();d.pop("METHOD_SET")
  self.assertFalse(test_gate(shadow_result=d))
 def test_38_unproved_display_format(self):
  self.assertFalse(test_gate(methodrows=rows("v1, v2, Landroid/util/Log;->w(Ljava/lang/String; Ljava/lang/String;)I")))
 def test_39_internal_display_whitespace(self):
  self.assertFalse(test_gate(methodrows=rows("v1, v2, Landroid/util/Log;->i(Ljava/lang/Str ing; Ljava/lang/String;)I")))
 def test_40_parse_exception_is_deny(self):
  self.assertFalse(test_gate(exception=RuntimeError("PRIVATE")))
 def test_41_all_source_only_no_real_claim(self):
  old=sys.argv;sys.argv=["p291"]
  try:
   out=io.StringIO()
   with contextlib.redirect_stdout(out):self.assertEqual(m.main(),0)
   self.assertIn("P291_CANDIDATE_REAL_DEX=NOT_ATTESTED",out.getvalue())
   self.assertIn("P291_RELEASE=DENY",out.getvalue())
  finally:sys.argv=old

if __name__=="__main__":unittest.main()
