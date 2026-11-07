#!/usr/bin/env python3
"""P172: CI-only Android36 GPU backend switch with preserved trust gates."""
from pathlib import Path
root=Path(__file__).resolve().parents[3]
workflow=(root/".github/workflows/p102-trusted-tool-binder.yml").read_text()
run=(root/"host_candidate/p102_trusted_tool/emulator/run_emulator_e2e.sh").read_text()
source=(root/"host_candidate/p102_trusted_tool/emulator/P102FixtureActivity.java").read_text()
def must(condition,msg):
    if not condition: raise AssertionError("P172_"+msg)
must(workflow.count("emulator-options: -no-snapshot -noaudio -no-boot-anim -gpu software")==1,
     "ANDROID36_SUPPORTED_SOFTWARE_GPU")
must("emulator-options: -no-snapshot -noaudio -no-boot-anim -gpu swiftshader_indirect" not in workflow,
     "DEPRECATED_ANDROID36_GPU_MUST_BE_ABSENT")
must("api-level: 36" in workflow and "P102_ANDROID_API=36 bash" in workflow,
     "ANDROID36_SEPARATE_REAL_EMULATOR")
must("P165 launch isolated Xvfb graphical display for Android36" in workflow,
     "GRAPHICAL_XVFB_MUST_STAY")
must("P166 provide confirmed libpulse runtime" in workflow,
     "GRAPHICS_RUNTIME_DEPENDENCY_MUST_STAY")
must(run.count("adb shell input tap")==1 and
     "P161_NATIVE_FOCUS_AND_PENDING_GENERATION_VERIFIED_BEFORE_CLICK=PASS" in run,
     "SINGLE_APPROVAL_WITH_NATIVE_FOCUS")
must("p102_native_focus_gate .p102tmp/filtered-log.txt" in run and
     "p162_os_resumed_app" in run and
     "P102_REAL_BINDER_PREGRANT_NO_EXECUTION=PASS" in run,
     "REAL_UI_AND_BINDER_PREGRANT_GATES")
must("P102_REAL_ANDROID36_BACKGROUND_REVOKE=PASS" not in run and
     "P102_NATIVE_BACKGROUND_REVOKE=PASS" in run,
     "OBSERVED_BACKGROUND_REVOKE")
must("onWindowFocusChanged(boolean hasFocus)" in source and
     "if(approveButton==null || pendingCallId==null || !hasWindowFocus()" in source,
     "GUEST_NATIVE_WINDOW_FOCUS_UNFORGED")
must("P102_REPLAY_REQUEST_DENIED=PASS" in run and
     "P102_TRUSTED_EXECUTION_COUNT=1" in run,
     "EXACTLY_ONCE_REPLAY_GATE")
print("P172_ANDROID36_SOFTWARE_GPU_CONFIG_WITH_NATIVE_SAFETY_UNCHANGED=PASS")
print("P172_FIX_IS_GPU_HYPOTHESIS_NOT_PRODUCTION_CONSENT=YES")
