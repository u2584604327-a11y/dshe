#!/usr/bin/env python3
"""P283: 35 synthetic adversarial DEX raw method ref / type tokenizer fixtures."""
import contextlib
import io
import sys
import unittest
sys.path[:0]=[
    "host_candidate/p283_descriptor_normalization",
    "host_candidate/p281_helper_predicates",
    "host_candidate/p269_method_pool",
    "host_candidate/p267_invoke_words",
    "host_candidate/p246_exception_semantics",
    "host_candidate/p249_dual_diff",
]
import p283_descriptor_normalization as mod
from p246_exception_semantics import Deny

class Op:
 def __init__(self,data):self.data=data
 def get_raw(self):return self.data
class Dex:
 def __init__(self,logargs=None,logowner=None,logname=None,logret=None):
    self.params={
     1:(mod.GETTER[0],mod.GETTER[1],(mod.GETTER[2],mod.GETTER[3])),
     2:(mod.LOG[0] if logowner is None else logowner,
        mod.LOG[1] if logname is None else logname,
        (mod.LOG[2] if logargs is None else logargs,
         mod.LOG[3] if logret is None else logret))
    }
 def get_cm_method(self,i):return self.params[i]

def row(log=True,spaced=True,raw=None):
    exp=mod.LOG if log else mod.GETTER
    idx=2 if log else 1
    args=("(Ljava/lang/String; Ljava/lang/String;)" if log and spaced
          else exp[2])
    output="v1, v2, "+exp[0]+"->"+exp[1]+args+exp[3]
    if raw is None:
        raw=(bytes((0x71,0x20,idx,0,0x21,0)) if log
             else bytes((0x71,0x10,idx,0,0,0)))
    return (0,"invoke-static",6,Op(raw),output)
def detail(log=True,dex=None,spaced=True,r=None):
    obj=Dex(logargs="(Ljava/lang/String; Ljava/lang/String;)") if dex is None else dex
    return mod.call_detail(row(log,spaced) if r is None else r,obj,
                           mod.LOG if log else mod.GETTER,2 if log else 1)
def sample():
    return {"witness":"ONE_ONLY",
            "calls":{"GETTER":detail(log=False,spaced=False),
                     "LOG":detail()}}

class Tests(unittest.TestCase):
 def test_01_args_empty(self):
    self.assertEqual(mod.canonical_args("()"),"()")
 def test_02_args_one_object(self):
    self.assertEqual(mod.canonical_args("(Ljava/lang/Object;)"),
                     "(Ljava/lang/Object;)")
 def test_03_args_two_objects_with_ascii_space(self):
    self.assertEqual(mod.canonical_args("(Ljava/lang/String; Ljava/lang/String;)"),
                     "(Ljava/lang/String;Ljava/lang/String;)")
 def test_04_args_tabs_as_separator(self):
    self.assertEqual(mod.canonical_args("(I\tJ\tLjava/lang/Object;)"),
                     "(IJLjava/lang/Object;)")
 def test_05_args_arrays(self):
    self.assertEqual(mod.canonical_args("([I [[Ljava/lang/String;)"),
                     "([I[[Ljava/lang/String;)")
 def test_06_arg_with_internal_whitespace_invalid(self):
    self.assertIsNone(mod.canonical_args("(Ljava/lang/Str ing;)"))
 def test_07_void_argument_invalid(self):
    self.assertIsNone(mod.canonical_args("(V)"))
 def test_08_missing_parenthesis_invalid(self):
    self.assertIsNone(mod.canonical_args("(Ljava/lang/Object;"))
 def test_09_comma_delimiter_invalid(self):
    self.assertIsNone(mod.canonical_args("(I,J)"))
 def test_10_unicode_space_invalid(self):
    self.assertIsNone(mod.canonical_args("(I\u2009J)"))
 def test_11_missing_class_semicolon_invalid(self):
    self.assertIsNone(mod.canonical_args("(Ljava/lang/String)"))
 def test_12_excessive_descriptor_invalid(self):
    self.assertIsNone(mod.canonical_args("("+("I"*9000)+")"))
 def test_13_return_void_valid(self):
    self.assertEqual(mod.canonical_return("V"),"V")
 def test_14_return_reference_valid(self):
    self.assertEqual(mod.canonical_return(" Ljava/lang/Object; "),"Ljava/lang/Object;")
 def test_15_return_array_valid(self):
    self.assertEqual(mod.canonical_return("[J"),"[J")
 def test_16_return_array_void_invalid(self):
    self.assertIsNone(mod.canonical_return("[V"))
 def test_17_return_two_types_invalid(self):
    self.assertIsNone(mod.canonical_return("II"))
 def test_18_log_display_exact_is_false_with_separator(self):
    self.assertEqual(detail()["OUTPUT_TEXT_EXACT"],"FAIL")
 def test_19_log_display_canonical_is_true(self):
    self.assertEqual(detail()["OUTPUT_TEXT_CANONICAL"],"PASS")
 def test_20_log_pool_args_exact_is_false(self):
    self.assertEqual(detail()["RAW_ARGS_EXACT"],"FAIL")
 def test_21_log_pool_args_canonical_true(self):
    self.assertEqual(detail()["RAW_ARGS_CANONICAL"],"PASS")
 def test_22_log_method_owner_name_ret_exact(self):
    q=detail()
    self.assertEqual([q[x] for x in ("RAW_OWNER","RAW_NAME","RAW_RETURN")],
                     ["PASS"]*3)
 def test_23_log_full_tuple_grammatical_match(self):
    self.assertEqual(detail()["RAW_CANONICAL_TUPLE"],"PASS")
 def test_24_log_format_only_candidate(self):
    self.assertEqual(mod.classify_detail(detail()),"FORMAT_ONLY_CANDIDATE")
 def test_25_getter_both_exact(self):
    q=detail(log=False,spaced=False)
    self.assertEqual(q["OUTPUT_TEXT_EXACT"],"PASS")
    self.assertEqual(q["RAW_ARGS_EXACT"],"PASS")
    self.assertEqual(mod.classify_detail(q),"EXACT")
 def test_26_real_owner_drift_never_normalizes(self):
    q=detail(dex=Dex(logargs="(Ljava/lang/String; Ljava/lang/String;)",
                     logowner="Landroid/util/Wrong;"))
    self.assertEqual(q["RAW_OWNER"],"FAIL")
    self.assertEqual(mod.classify_detail(q),"DIFFERENT_OR_INVALID")
 def test_27_real_method_name_drift_never_normalizes(self):
    q=detail(dex=Dex(logargs="(Ljava/lang/String; Ljava/lang/String;)",
                     logname="w"))
    self.assertEqual(q["RAW_NAME"],"FAIL")
 def test_28_real_proto_drift_never_normalizes(self):
    q=detail(dex=Dex(logargs="(Ljava/lang/String;Ljava/lang/Object;)"))
    self.assertEqual(q["RAW_ARGS_CANONICAL"],"FAIL")
 def test_29_return_drift_never_normalizes(self):
    q=detail(dex=Dex(logargs="(Ljava/lang/String; Ljava/lang/String;)",
                     logret="V"))
    self.assertEqual(q["RAW_RETURN"],"FAIL")
 def test_30_invalid_raw_opcode_unverified(self):
    q=detail(r=row(raw=b"\x00\x20\x02\x00\x21\x00"))
    self.assertEqual(q["RAW_CANONICAL_TUPLE"],"UNVERIFIED")
 def test_31_exact_public_schema_and_deny(self):
    q=sample();o=io.StringIO()
    with contextlib.redirect_stdout(o):self.assertEqual(mod.emit(q),2)
    s=o.getvalue()
    self.assertIn("P283_LOG_CLASS=FORMAT_ONLY_CANDIDATE",s)
    self.assertIn("P283_RELEASE=DENY",s)
    self.assertNotIn(mod.LOG[0],s)
 def test_32_forged_output_rejected(self):
    q=sample();q["calls"]["LOG"]["RAW_CANONICAL_TUPLE"]="OVERRIDE"
    with self.assertRaises(Deny):mod.emit(q)
 def test_33_fake_tuple_pass_rejected(self):
    q=sample();q["calls"]["LOG"]["RAW_OWNER"]="FAIL"
    with self.assertRaises(Deny):mod.emit(q)
 def test_34_display_exact_without_canonical_rejected(self):
    q=sample();q["calls"]["LOG"]["OUTPUT_TEXT_EXACT"]="PASS"
    q["calls"]["LOG"]["OUTPUT_TEXT_CANONICAL"]="FAIL"
    with self.assertRaises(Deny):mod.emit(q)
 def test_35_source_only_no_real_claim(self):
    old=sys.argv;sys.argv=["p283"]
    try:
        o=io.StringIO()
        with contextlib.redirect_stdout(o):self.assertEqual(mod.main(),0)
        self.assertIn("P283_REAL_INVOCATION_DESCRIPTOR=NOT_ATTESTED",o.getvalue())
        self.assertIn("P283_RELEASE=DENY",o.getvalue())
    finally:sys.argv=old

if __name__=="__main__":unittest.main()
