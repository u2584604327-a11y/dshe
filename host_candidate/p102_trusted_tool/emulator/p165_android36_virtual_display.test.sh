#!/usr/bin/env bash
set -euo pipefail
file="$(dirname "$0")/p165_android36_virtual_display.sh"
bash -n "$file"
# Static refusal boundaries: this workflow cannot send synthetic approval
# before the framework UI has independently proven native focus.
grep -Fq 'GITHUB_ACTIONS' "$file"
grep -Fq 'GITHUB_REPOSITORY' "$file"
grep -Fq 'Xvfb :96 -screen 0 1280x900x24 -nolisten tcp' "$file"
grep -Fq 's.connect("/tmp/.X11-unix/X96")' "$file"
if grep -Fq 'xdpyinfo' "$file" && ! grep -Fq 'No x11-utils / xdpyinfo package dependency' "$file";then
  echo P165_UNEXPECTED_X11_UTILS_DEPENDENCY=FAIL;exit 1
fi
grep -Fq 'P165_NATIVE_CONSENT_WAS_NOT_INJECTED=YES' "$file"
if grep -Eq 'adb|input tap|am start|sdkmanager|apt-get|curl |wget |wm dismiss-keyguard' "$file";then
  echo P165_UNAPPROVED_EMULATOR_CONTROL_IN_DISPLAY_HELPER=FAIL;exit 1
fi
set +e
out="$(env -u GITHUB_ACTIONS bash "$file" 2>&1)"
code=$?
set -e
[[ "$code" -eq 2 && "$out" == *'P165_GITHUB_CI_SCOPE=DENIED'* ]] || {
  echo P165_NON_CI_REFUSAL_FAILED;exit 1;
}
echo P165_CI_SCOPE_NO_APPROVAL_AND_STATIC_NEGATIVES=PASS
