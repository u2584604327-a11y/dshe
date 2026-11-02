#!/usr/bin/env python3
"""P169: reject consent bypasses; only a disposable lab Activity screen hint."""
from pathlib import Path
base=Path(__file__).resolve().parent
java=(base/"P102FixtureActivity.java").read_text()
script=(base/"run_emulator_e2e.sh").read_text()
require=lambda ok,msg:ok or (_ for _ in ()).throw(AssertionError(msg))
require(java.count("setTurnScreenOn(true);")==1,"P169_ACTIVITY_WAKE_ONCE")
require(java.count("addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);")==1,"P169_KEEP_SCREEN_ONCE")
require(java.count("P102_NATIVE_WINDOW_FOCUS=")==1,"P169_NATIVE_FOCUS_CALLBACK_MUST_REMAIN_REAL")
require("!hasWindowFocus()" in java,"P169_NATIVE_VISIBLE_RECT_MUST_REQUIRE_FOCUS")
require("getGlobalVisibleRect(r)" in java,"P169_NATIVE_BUTTON_RECT_MUST_REMAIN_REAL")
require("P102_NATIVE_UI_APPROVAL_DISPATCH=" in java,"P169_DO_NOT_REMOVE_REAL_NATIVE_APPROVAL")
require(script.count("adb shell am start -W -n com.dsh.p102.trustedtoolprobe/.P102FixtureActivity")==1,"P169_ONE_WAITED_ACTIVITY_LAUNCH")
require(script.count("adb shell input tap")==1,"P169_ONE_NATIVE_CLICK_ONLY")
require("p102_native_focus_gate .p102tmp/filtered-log.txt" in script,"P169_NATIVE_FOCUS_AND_GENERATION_MUST_STILL_GUARD")
require("p162_os_resumed_app" in script,"P169_ANDROID36_OS_RESUMED_GATE_MUST_REMAIN")
require("P169_NATIVE_WINDOW_FOCUS_STILL_REQUIRED=YES" in script,"P169_LAUNCH_CANNOT_IMPLY_CONSENT")
require("P102_TRUSTED_EXECUTION_COUNT=1" in script and "P102_REPLAY_REQUEST_DENIED=PASS" in script,"P169_EXACTLY_ONCE_REPLAY_MUST_REMAIN")
print("P169_ONLY_SYNTHETIC_LAUNCH_AND_SCREEN_HINT=PASS")
print("P169_NATIVE_FOCUS_GENERATION_ONCE_AND_REPLAY_UNCHANGED=PASS")
