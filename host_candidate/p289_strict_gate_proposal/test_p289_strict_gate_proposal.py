#!/usr/bin/env python3
"""P289: actual raw 35c word, method target, independent original gate tests."""
import contextlib,io,sys,unittest
from unittest.mock import patch
sys.path[:0]=[
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
import p289_strict_gate_proposal as m
from p246_exception_semantics import Deny
from p281_helper_predicates import PREDICATES,OWNER,NAME,DESC
from p285_shadow_verifier import FACTORS
from p287_gate_delta import CHECKS

class Inst:
 def __init__(self,raw):self.raw=raw
 def get_raw(self):return self.raw
class Dex:
 def __init__(self,reference=None):
    self.ref=("Landroid/util/Log;","i",("(Ljava/lang/String; Ljava/lang/String;)","I")) if reference is None else reference
 def get_cm_method(self,index):
    if index!=0x1234:raise IndexError("PRIVATE")
    return self.ref
def row(data=None,op="invoke-static"):
 if data is None:data=bytes((0x71,0x20,0x34,0x12,0x21,0x00))
 return (0,op,6,Inst(data),"DISPLAY_UNTRUSTED")
def checks():
 return {k:"PASS" for k in m.CHECKS289}
def pred():
 return {k:(False if k==PREDICATES[4] else True) for k in PREDICATES}
def ready_checks():
 return {k:"PASS" for k in CHECKS}
def shadow():
 return {k:"PASS" for k in FACTORS}
def combined():
 base=object();candidate=Dex()  # candidate must expose real-like indexed method pool
 def idx(v):
    if v is base:return {"old":object()}
    return {"old":object(),(OWNER,NAME,DESC):object()}
 get=p245_checks={"rows":[(0,"nop",2,None,"")]*10+[row()]+[(0,"return-void",2,None,"")]*3,
                   "predicates":pred()}
 def patched_p287(*args):
    return ready_checks(),"SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE"
 with patch.object(m,"index",side_effect=idx),\
      patch.object(m,"p245_checks",return_value=get),\
      patch.object(m,"shadow_audit",return_value=shadow()),\
      patch.object(m,"delta_audit",side_effect=patched_p287):
    return m.judge(base,candidate)

class Tests(unittest.TestCase):
 def test_01_raw_exact_positive(self):
    self.assertEqual(m.raw_log_target(row(),Dex()),
                     {k:"PASS" for k in m.CHECKS289[2:8]})
 def test_02_ascii_param_intertype_space_allowed(self):
    self.assertEqual(m.raw_log_target(row(),Dex())["RAW_LOG_DEX_ARGS"],"PASS")
 def test_03_multiple_ascii_param_separators_allowed(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;\t Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"PASS")
 def test_04_wrong_opcode_denied(self):
    q=m.raw_log_target(row(data=bytes((0x70,0x20,0x34,0x12,0x21,0x00))),Dex())
    self.assertEqual(q["RAW_LOG_35C_FORMAT"],"FAIL")
 def test_05_wrong_opcode_name_denied(self):
    self.assertEqual(m.raw_log_target(row(op="invoke-direct"),Dex())["RAW_LOG_35C_FORMAT"],"FAIL")
 def test_06_wrong_count_denied(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x10,0x34,0x12,0x21,0))),Dex())["RAW_LOG_35C_FORMAT"],"FAIL")
 def test_07_nonzero_unused_g_denied(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x21,0x34,0x12,0x21,0))),Dex())["RAW_LOG_35C_FORMAT"],"FAIL")
 def test_08_nonzero_unused_register_denied(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x20,0x34,0x12,0x21,1))),Dex())["RAW_LOG_35C_FORMAT"],"FAIL")
 def test_09_registers_swapped_denied(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x20,0x34,0x12,0x12,0))),Dex())["RAW_LOG_35C_REGISTERS"],"FAIL")
 def test_10_registers_mismatch_denied(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x20,0x34,0x12,0x31,0))),Dex())["RAW_LOG_35C_REGISTERS"],"FAIL")
 def test_11_unavailable_method_index_unverified(self):
    self.assertEqual(m.raw_log_target(row(data=bytes((0x71,0x20,0x01,0x00,0x21,0))),Dex())["RAW_LOG_DEX_OWNER"],"UNVERIFIED")
 def test_12_wrong_owner_denied(self):
    d=Dex(("Landroid/util/Other;","i",("(Ljava/lang/String;Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_OWNER"],"FAIL")
 def test_13_wrong_method_denied(self):
    d=Dex(("Landroid/util/Log;","w",("(Ljava/lang/String;Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_METHOD"],"FAIL")
 def test_14_wrong_first_param_denied(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/Object;Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"FAIL")
 def test_15_wrong_second_param_denied(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;Ljava/lang/Object;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"FAIL")
 def test_16_missing_second_argument_denied(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"FAIL")
 def test_17_extra_argument_denied(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;Ljava/lang/String;I)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"FAIL")
 def test_18_type_internal_space_unverified(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/Str ing;Ljava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"UNVERIFIED")
 def test_19_void_argument_unverified(self):
    d=Dex(("Landroid/util/Log;","i",("(VLjava/lang/String;)","I")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_ARGS"],"UNVERIFIED")
 def test_20_wrong_return_denied(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;Ljava/lang/String;)","V")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_RETURN"],"FAIL")
 def test_21_invalid_return_unverified(self):
    d=Dex(("Landroid/util/Log;","i",("(Ljava/lang/String;Ljava/lang/String;)","II")))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_RETURN"],"UNVERIFIED")
 def test_22_malformed_ref_tuple_unverified(self):
    self.assertEqual(m.raw_log_target(row(),Dex(reference=("Landroid/util/Log;",)) )["RAW_LOG_DEX_OWNER"],"UNVERIFIED")
 def test_23_malformed_ref_proto_unverified(self):
    d=Dex(reference=("Landroid/util/Log;","i",["notproto"]))
    self.assertEqual(m.raw_log_target(row(),d)["RAW_LOG_DEX_OWNER"],"UNVERIFIED")
 def test_24_missing_instruction_unverified(self):
    self.assertEqual(m.raw_log_target((0,"invoke-static",6,None),Dex())["RAW_LOG_35C_FORMAT"],"UNVERIFIED")
 def test_25_empty_raw_unverified(self):
    self.assertEqual(m.raw_log_target(row(data=b""),Dex())["RAW_LOG_35C_FORMAT"],"UNVERIFIED")
 def test_26_positive_all_raw_and_shadow_review(self):
    self.assertEqual(combined(),checks())
 def test_27_forged_failure_in_original_four_is_deny(self):
    original=m.p245_checks
    base=object();derived=object()
    with patch.object(m,"index",side_effect=[{"old":1},{"old":1,(OWNER,NAME,DESC):2}]),\
        patch.object(m,"p245_checks",return_value={"rows":[row()]*14,
          "predicates":{k:(False if k==PREDICATES[0] else True) for k in PREDICATES}}),\
        patch.object(m,"shadow_audit",return_value=shadow()),\
        patch.object(m,"delta_audit",return_value=(ready_checks(),"SAFE_FORMAT_DELTA_CANDIDATE_NOT_GATE")):
        self.assertEqual(m.judge(base,derived)["ORIGINAL_FOUR_HELPER_CONDITIONS"],"FAIL")
 def test_28_aggregate_p285_failure_is_deny(self):
    d=checks();d["P285_ELEVEN_INVARIANTS"]="FAIL"
    out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(m.emit(d),2)
    self.assertIn("P289_SOURCE_CHANGE_REVIEW=DENY",out.getvalue())
 def test_29_aggregate_p287_failure_is_deny(self):
    d=checks();d["P287_ALL_SEVEN_REVIEW_ITEMS"]="FAIL"
    out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(m.emit(d),2)
    self.assertIn("P289_SOURCE_CHANGE_REVIEW=DENY",out.getvalue())
 def test_30_unverified_ref_denies(self):
    d=checks();d["RAW_LOG_DEX_METHOD"]="UNVERIFIED"
    out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(m.emit(d),2)
    self.assertIn("P289_SOURCE_CHANGE_REVIEW=DENY",out.getvalue())
 def test_31_all_pass_cannot_release(self):
    out=io.StringIO()
    with contextlib.redirect_stdout(out):self.assertEqual(m.emit(checks()),2)
    self.assertIn("P289_SOURCE_CHANGE_REVIEW=STRICT_REPLACEMENT_PROPOSAL_ONLY",out.getvalue())
    self.assertIn("P289_RELEASE=DENY",out.getvalue())
    self.assertIn("P289_REPLACEMENT_IN_MAINLINE=NOT_AUTHORIZED",out.getvalue())
 def test_32_fake_public_schema_denied(self):
    d=checks();d["UNSAFE_BYPASS"]="PASS"
    with self.assertRaises(Deny):m.emit(d)
 def test_33_invalid_status_denied(self):
    d=checks();d["RAW_LOG_DEX_OWNER"]="ALLOW"
    with self.assertRaises(Deny):m.emit(d)
 def test_34_source_only_never_claims_real(self):
    old=sys.argv;sys.argv=["p289"]
    try:
        out=io.StringIO()
        with contextlib.redirect_stdout(out):self.assertEqual(m.main(),0)
        self.assertIn("P289_REAL_RAW_METHOD_REF=NOT_ATTESTED",out.getvalue())
        self.assertIn("P289_RELEASE=DENY",out.getvalue())
    finally:sys.argv=old

if __name__=="__main__":unittest.main()
