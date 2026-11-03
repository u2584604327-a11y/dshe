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
# P180 WMS subtype evidence: no trust escalation, and no arbitrary raw
# WindowState/user text must be included in any published diagnostic.
kind_cases=[
 ("com.android.systemui/NotificationShade", "NOTIFICATION_SHADE"),
 ("com.android.systemui/QuickSettingsPanel", "NOTIFICATION_SHADE"),
 ("com.android.systemui/StatusBarWindow", "STATUS_BAR"),
 ("com.android.systemui/NavigationBar", "NAVIGATION_BAR"),
 ("com.android.systemui/ScreenDecorOverlay", "SCREEN_DECOR"),
 ("com.android.systemui/VolumeDialog", "VOLUME_DIALOG"),
 ("com.android.systemui/GlobalActionsDialog", "GLOBAL_ACTIONS"),
 ("com.android.systemui/Recents", "RECENTS"),
 ("com.android.systemui/Unrecognized SecretOrder-54321", "OTHER_SYSTEMUI"),
 ("com.android.systemui/keyguard.KeyguardView", "KEYGUARD"),
 ("com.private.bank/SecretPassword-888", "NOT_SYSTEMUI"),
 ("null", "NOT_SYSTEMUI"),
]
allowed={y for _,y in kind_cases}|{"OVERSIZE","UNAVAILABLE"}
for window,expect in kind_cases:
    raw="mCurrentFocus=Window{private u0 "+window+"}\\n"
    actual=mod.focused_window_kind(raw)
    assert actual==expect,(window,actual,expect)
    assert actual in allowed and "Secret" not in actual
assert mod.focused_window_kind("")=="UNAVAILABLE"
assert mod.focused_window_kind("A"*(mod.MAX_BYTES+1))=="OVERSIZE"
assert mod.focused_window_kind(
    "mCurrentFocus=Window{u0 com.android.systemui/NotificationShade}\\n"
    "mCurrentFocus=Window{u0 com.android.systemui/NavigationBar}\\n"
)=="NAVIGATION_BAR"
assert 'P180_WM_FOCUSED_WINDOW_KIND=' in p.read_text()
print("P180_ANDROID36_SYSTEMUI_SUBTYPE_PRIVACY_REDACTED_READONLY=PASS")
script=Path(__file__).with_name("run_emulator_e2e.sh").read_text()
# The Android16 focus evidence is independently read at TWO scoped points:
# P176's sole non-consent SYSTEMUI environment candidate, then P175's final
# hard-failed consent diagnostic. The legacy windows fallback is inside P175
# only. None of these WMS values may authorize input or tool execution.
assert script.count('adb shell dumpsys window displays 2>/dev/null')==2
assert script.count('adb shell dumpsys window windows 2>/dev/null')==1
assert 'python3 "$(dirname "$0")/p174_window_manager_focus.py"' in script
p175_start=script.index("  # P175:")
p176_start=script.index("    # P176:")
p175_end=script.index("  # P164:",p175_start)
p175=script[p175_start:p175_end]
assert p176_start < script.index("P102_NATIVE_BUTTON_UNAVAILABLE_AFTER_BOUNDED_POLL") < p175_start
assert p175.count('adb shell dumpsys window displays 2>/dev/null')==1
assert p175.count('adb shell dumpsys window windows 2>/dev/null')==1
assert p175.index('adb shell dumpsys window displays 2>/dev/null') < p175.index('adb shell dumpsys window windows 2>/dev/null')
assert p175_end < script.index("  exit 1\nfi\nread -r X Y")
assert script.index("P175_WM_FOCUS_SOURCE=DISPLAYS") < script.index("P175_WM_FOCUS_SOURCE=WINDOWS") < script.index("P175_WM_FOCUS_SOURCE=UNAVAILABLE")
assert script.count("P175_WM_FOCUS_SOURCE=")==3
assert "grep -Eq '^[[:space:]]*m(CurrentFocus|FocusedApp)[[:space:]]*='" in script
for unsafe in ("adb shell am start", "adb shell input tap"):
    assert unsafe not in script[script.index("  # P175:"):script.index("  # P164:",script.index("  # P175:"))]
display_record=("WINDOW MANAGER DISPLAY CONTENTS\n  DisplayContent{a displayId=0}\n"
                "      mCurrentFocus=Window{11 u0 com.android.systemui/keyguard.KeyguardView}\n"
                "      mFocusedApp=ActivityRecord{22 u0 "+lab+"/.P102FixtureActivity t1}\n")
assert mod.summarize(display_record)==("KEYGUARD","LAB","UNKNOWN")
# P176: requires all three independent genuine OS WMS predicates,
# OS ActivityManager top-resumed, and a once-only delayed trial inside the
# Android36 branch. This statusbar command is NOT approval, input tap,
# activity start, synthetic focus or privilege grant.
assert script.count('adb shell cmd statusbar collapse')==1
p176=script[script.index('    # P176:'):script.index('    if COORDS="$(python3')]
assert '[[ "$attempt" == 12 ]] && p162_os_resumed_app' in p176
assert "adb shell dumpsys window displays 2>/dev/null" in p176
assert "P174_WM_CURRENT_FOCUS_CATEGORY=SYSTEMUI" in p176
assert "P174_WM_FOCUSED_APP_CATEGORY=LAB" in p176
assert "P174_WM_KEYGUARD_SHOWING=NO" in p176
assert "P176_SYSTEMUI_SHADE_COLLAPSE_REQUESTED=PASS_REQUEST_ONLY" in p176
assert "P176_SYSTEMUI_SHADE_COLLAPSE=SKIPPED_NOT_PROVEN" in p176
assert "P102_PREAPPROVAL_REQUEST_GATE=PASS" in p176
assert 'P102_TRUSTED_EXECUTION_COUNT=' in p176
assert "adb shell input tap" not in p176
assert "am start" not in p176 and "wm dismiss-keyguard" not in p176
assert script.count('adb shell input tap "$X" "$Y"')==1
print("P176_ONCE_ONLY_SYSTEMUI_SHADE_RECOVERY_NEVER_GRANTS_CONSENT=PASS")
print("P175_ANDROID16_WINDOW_DISPLAYS_FOCUS_SOURCE_FIRST_AND_LEGACY_FALLBACK=PASS")
assert "adb shell input tap \"$X\" \"$Y\"" in script
assert "p102_native_focus_gate .p102tmp/filtered-log.txt" in script
assert "P102_TRUSTED_EXECUTION_COUNT=1" in script
assert "P102_REPLAY_REQUEST_DENIED=PASS" in script
assert "P102_NATIVE_BACKGROUND_REVOKE=PASS" in script
print("P174_READ_ONLY_WINDOW_MANAGER_FOCUS_DIAGNOSTIC_CASES=PASS")
print("P174_NO_RAW_PRIVATE_WINDOW_DETAILS_OR_NATIVE_CONSENT_BYPASS=PASS")
