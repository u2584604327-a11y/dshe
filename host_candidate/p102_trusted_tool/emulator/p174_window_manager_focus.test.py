#!/usr/bin/env python3
"""P174 parser positives and privacy negatives, no ADB use."""
import importlib.util
from pathlib import Path
p=Path(__file__).with_name("p174_window_manager_focus.py")
spec=importlib.util.spec_from_file_location("p174",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
lab="com.dsh.p102.trustedtoolprobe"
cases=[
 ("  mCurrentFocus=Window{a u0 "+lab+"/.P102FixtureActivity}\n  mFocusedApp=ActivityRecord{b u0 "+lab+"/.P102FixtureActivity}\n",("LAB","LAB","UNKNOWN")),
 (" mCurrentFocus=Window{0 u0 com.android.systemui/keyguard.KeyguardView}\n mFocusedApp=ActivityRecord{0 u0 "+lab+"/.P102FixtureActivity}\n mShowingLockscreen=true\n",("KEYGUARD","LAB","YES")),
 ("  mCurrentFocus=null\n  mFocusedApp=ActivityRecord{a u0 "+lab+"/.P102FixtureActivity}\n",("NONE","LAB","UNKNOWN")),
 ("mCurrentFocus=Window{a u0 com.android.systemui/NotificationShade}\nmFocusedApp=null\nmKeyguardShowing=false\n",("SYSTEMUI","NONE","NO")),
 ("mCurrentFocus=Window{secret u0 com.private.bank/Welcome Account-1234}\nmFocusedApp=ActivityRecord{secret u0 com.private.bank/.Main}\n",("OTHER","OTHER","UNKNOWN")),
 ("",("UNAVAILABLE","UNAVAILABLE","UNKNOWN")),
]
for raw,expected in cases:
    assert mod.summarize(raw)==expected,(expected,mod.summarize(raw))
assert mod.summarize("A"*(mod.MAX_BYTES+1))==("OVERSIZE","OVERSIZE","UNKNOWN")
script=Path(__file__).with_name("run_emulator_e2e.sh").read_text()
assert script.count('adb shell dumpsys window windows 2>/dev/null')==1
assert 'python3 "$(dirname "$0")/p174_window_manager_focus.py"' in script
assert script.index("P102_NATIVE_BUTTON_UNAVAILABLE_AFTER_BOUNDED_POLL") < script.index("adb shell dumpsys window windows 2>/dev/null") < script.index("  exit 1\nfi\nread -r X Y")
assert "adb shell input tap \"$X\" \"$Y\"" in script
assert "p102_native_focus_gate .p102tmp/filtered-log.txt" in script
assert "P102_TRUSTED_EXECUTION_COUNT=1" in script
assert "P102_REPLAY_REQUEST_DENIED=PASS" in script
assert "P102_NATIVE_BACKGROUND_REVOKE=PASS" in script
print("P174_READ_ONLY_WINDOW_MANAGER_FOCUS_DIAGNOSTIC_CASES=PASS")
print("P174_NO_RAW_PRIVATE_WINDOW_DETAILS_OR_NATIVE_CONSENT_BYPASS=PASS")
