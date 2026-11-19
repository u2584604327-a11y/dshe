#!/usr/bin/env python3
import importlib.util
from pathlib import Path
file=Path(__file__).with_name("p162_native_visible_rect.py")
spec=importlib.util.spec_from_file_location("p162",file)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
base="\n".join([
"P102_NATIVE_WINDOW_FOCUS=YES",
"P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS",
"P102_PREAPPROVAL_REQUEST_GATE=PASS",
"P162_VISIBLE_NATIVE_APPROVAL_RECT=0,48,400,800",
])
assert m.verified_center(base)==(200,424)
def deny(text):
    try:m.verified_center(text)
    except ValueError:return
    raise AssertionError("P162_UNSAFE_NATIVE_RECT_ACCEPTED")
deny(base.replace("P102_NATIVE_WINDOW_FOCUS=YES","P102_NATIVE_WINDOW_FOCUS=NO"))
deny(base.replace("P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS",""))
deny(base+"\nP102_NATIVE_BACKGROUND_REVOKE=PASS")
deny(base+"\nP102_NATIVE_WINDOW_FOCUS=NO")
deny(base+"\nP102_NATIVE_UI_APPROVAL_DISPATCH=NO")
deny(base+"\nP102_TRUSTED_EXECUTION_COUNT=1")
deny(base.replace("0,48,400,800","0,48,400,800"+"\n"+"P162_VISIBLE_NATIVE_APPROVAL_RECT=0,48,600,900"))
deny(base.replace("0,48,400,800","10,10,10,10"))
deny(base.replace("P162_VISIBLE_NATIVE_APPROVAL_RECT=0,48,400,800",""))
deny("P162_VISIBLE_NATIVE_APPROVAL_RECT=0,48,400,800\n"+base.replace("P162_VISIBLE_NATIVE_APPROVAL_RECT=0,48,400,800",""))
print("P162_NATIVE_RECT_STALE_REVOKED_OR_UNFOCUSED_NEGATIVES=PASS")
print("P162_NO_NATIVE_CLICK_OR_APPROVAL_IN_UNIT_TEST=YES")
