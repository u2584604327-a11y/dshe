#!/usr/bin/env python3
"""P179: STATIC native-consent safety regression, never drives a device."""
from pathlib import Path
base=Path(__file__).resolve().parent
script=(base/"run_emulator_e2e.sh").read_text(encoding="utf-8")
work=(base.parents[2]/".github/workflows/p102-trusted-tool-binder.yml").read_text(encoding="utf-8")
start=script.index("p164_prepare_disposable_emulator_ui")
reset=script.index("adb shell input keyevent KEYCODE_HOME")
launch=script.index('adb shell am start -W -n com.dsh.p102.trustedtoolprobe/.P102FixtureActivity')
pending=script.index("P102_REAL_BINDER_PREGRANT_NO_EXECUTION=PASS")
tap=script.index('adb shell input tap "$X" "$Y"')
assert start < reset < launch < pending < tap
assert script.count("adb shell input keyevent KEYCODE_HOME")==1
assert script.count('adb shell am start -W -n com.dsh.p102.trustedtoolprobe/.P102FixtureActivity')==1
assert script.count('adb shell input tap "$X" "$Y"')==1
assert script.count('adb shell cmd statusbar collapse')==1
guard=script[script.index("# P179:"):script.index("# P169:")]
assert 'if [[ "$P102_ANDROID_API" == 36 ]]' in guard
for key in ("ANDROID_SERIAL","emulator-5554","ro.kernel.qemu","sys.boot_completed"):
    assert key in guard,key
assert "P179_ANDROID36_PRELAUNCH_HOME_REQUESTED=PASS_REQUEST_ONLY" in guard
for forbidden in ("am start", "input tap", "statusbar collapse",
                  "P102_TRUSTED_EXECUTION_COUNT=1","P102_NATIVE_UI_APPROVAL_DISPATCH=YES"):
    # Exclude explanatory comments, assert actions never bypass consent.
    live="\n".join(s for s in guard.splitlines() if not s.lstrip().startswith("#"))
    assert forbidden not in live,forbidden
assert "p102_native_focus_gate .p102tmp/filtered-log.txt" in script
assert "p162_os_resumed_app" in script
assert 'P102_REAL_BINDER_PREGRANT_NO_EXECUTION=PASS' in script
assert 'P102_TRUSTED_EXECUTION_COUNT=1' in script
assert 'P102_REPLAY_REQUEST_DENIED=PASS' in script
assert "p179_android36_prelaunch_home.test.py" in work
print("P179_ANDROID36_PRELAUNCH_ONLY_HOME_SAFETY=PASS_STATIC")
print("P179_REAL_NATIVE_FOCUS_AND_ONE_TAP_UNMODIFIED=PASS_STATIC")
print("P179_PRODUCTION_ENGINE_MANAGER=NOT_WIRED")
