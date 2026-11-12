#!/usr/bin/env python3
"""P249 26 fixture tests; synthetic methods only, no real APK bytes."""
import contextlib,io,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,"host_candidate/p246_exception_semantics")
from test_p246_exception_semantics import A,Code,Dex,Handler,Method,Pair,Table,Try
from p246_exception_semantics import Deny
from p249_dual_diff import START,OWNER,HELPER,dual,emit,seal
D=Dex()
EARLY=("Lfake/AA;","m","()V")
LATE=("Lfake/ZZ;","m","()V")
def m():return Method()
def long():return Method(code=Code(total=7),widths=[2,2,2,2,2,4])
def desc():return Method(code=Code(table=Table([Handler(pairs=[Pair(4,3)])])))
def target():return Method(code=Code(table=Table([Handler(pairs=[Pair(3,4)])])))
def catch():return Method(code=Code(table=Table([Handler(size=-1,catch=4)])))
def span():return Method(code=Code(tries=[Try(start=1,width=2)]))
def both():return Method(code=Code(total=7,table=Table([Handler(pairs=[Pair(4,3)])])),widths=[2,2,2,2,2,4])
def check(a=None,b=None,od=D,dd=D):
    return dual({START:m()} if a is None else a,
                {START:m()} if b is None else b,od,dd)
class NoCode:
 def get_code(self):return None
class Tests(unittest.TestCase):
 def test_01_same(self):
    q=check();self.assertEqual((q["code_category"],q["exception_category"]),("NONE","NONE"))
 def test_02_only_code_size(self):
    q=check({START:m()},{START:long()})
    self.assertEqual((q["code_category"],q["exception_category"]),("CODE_SIZE","NONE"))
 def test_03_only_exception(self):
    q=check({START:m()},{START:desc()})
    self.assertEqual((q["code_category"],q["exception_category"]),("NONE","TYPE_DESCRIPTOR"))
 def test_04_both_same_method(self):
    q=check({START:m()},{START:both()})
    self.assertEqual((q["code_category"],q["exception_category"]),("CODE_SIZE","TYPE_DESCRIPTOR"))
 def test_05_code_other_exc_start(self):
    q=check({EARLY:m(),START:m()},{EARLY:long(),START:target()})
    self.assertEqual((q["code_group"],q["exception_group"]),("OTHER_PRIMARY","START_COROUTINE"))
 def test_06_code_start_exc_other(self):
    q=check({START:m(),LATE:m()},{START:long(),LATE:catch()})
    self.assertEqual((q["code_group"],q["exception_group"]),("START_COROUTINE","OTHER_PRIMARY"))
 def test_07_first_code_sorted(self):
    q=check({EARLY:m(),LATE:m()},{EARLY:long(),LATE:long()})
    self.assertEqual(q["code_group"],"OTHER_PRIMARY")
 def test_08_first_exception_sorted(self):
    q=check({EARLY:m(),START:m()},{EARLY:target(),START:desc()})
    self.assertEqual(q["exception_category"],"TYPED_TARGET")
 def test_09_handler_order(self):
    x=Method(code=Code(table=Table([Handler(size=2,pairs=[Pair(3,3),Pair(4,4)])])))
    y=Method(code=Code(table=Table([Handler(size=2,pairs=[Pair(4,4),Pair(3,3)])])))
    self.assertEqual(check({START:x},{START:y})["exception_category"],"HANDLER_ORDER")
 def test_10_target(self):self.assertEqual(check({START:m()},{START:target()})["exception_category"],"TYPED_TARGET")
 def test_11_catchall(self):self.assertEqual(check({START:m()},{START:catch()})["exception_category"],"CATCHALL_PRESENCE")
 def test_12_try_span(self):self.assertEqual(check({START:m()},{START:span()})["exception_category"],"TRY_SPAN")
 def test_13_typed_count(self):
    y=Method(code=Code(table=Table([Handler(size=2,pairs=[Pair(3,3),Pair(4,4)])])))
    self.assertEqual(check({START:m()},{START:y})["exception_category"],"TYPED_COUNT")
 def test_14_pool_reindex_semantic_same(self):
    y=Method(code=Code(table=Table([Handler(pairs=[Pair(33,3)])])))
    self.assertEqual(check({START:m()},{START:y},D,Dex({33:A}))["exception_category"],"NONE")
 def test_15_relative_handler_off_same(self):
    y=Method(code=Code(tries=[Try(off=4)],table=Table([Handler(off=204)],base=200)))
    self.assertEqual(check({START:m()},{START:y})["exception_category"],"NONE")
 def test_16_extra_method_deny(self):
    with self.assertRaises(Deny):check({START:m()},{START:m(),EARLY:m()})
 def test_17_missing_method_deny(self):
    with self.assertRaises(Deny):check({START:m(),EARLY:m()},{START:m()})
 def test_18_exact_allowed_helper_only(self):
    self.assertEqual(check({START:m()},{START:m(),HELPER:m()})["code_gate"],"PARITY")
 def test_19_helper_and_other_deny(self):
    with self.assertRaises(Deny):check({START:m()},{START:m(),HELPER:m(),EARLY:m()})
 def test_20_code_presence_deny(self):
    with self.assertRaises(Deny):check({START:m()},{START:NoCode()})
 def test_21_bad_original_decode_deny(self):
    with self.assertRaises(Deny):check({START:Method(widths=[2,2,2,2,2,0])},{START:m()})
 def test_22_bad_derived_decode_deny(self):
    with self.assertRaises(Deny):check({START:m()},{START:Method(widths=[2,2,2,2,2,0])})
 def test_23_unbound_handler_deny(self):
    y=Method(code=Code(table=Table([Handler(),Handler(off=102)])))
    with self.assertRaises(Deny):check({START:m()},{START:y})
 def test_24_empty_code_set_deny(self):
    with self.assertRaises(Deny):check({START:NoCode()},{START:NoCode()})
 def test_25_sanitized_report_and_parity_not_release(self):
    for q,rc in ((check({START:m()},{START:both()}),2),(check(),0)):
        buf=io.StringIO()
        with contextlib.redirect_stdout(buf):self.assertEqual(emit(q),rc)
        self.assertNotIn(OWNER,buf.getvalue())
        self.assertNotIn(A,buf.getvalue())
        self.assertIn("P249_UNCHANGED_P245_FULL_STATIC_GATE=NOT_ATTESTED",buf.getvalue())
 def test_26_fake_signed_pin_deny(self):
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/"fake.apk";p.write_bytes(b"fake")
        with self.assertRaises(Deny):seal(p)
if __name__=="__main__":unittest.main()
