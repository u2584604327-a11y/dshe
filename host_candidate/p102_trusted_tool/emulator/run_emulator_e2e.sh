#!/usr/bin/env bash
set -euo pipefail
adb wait-for-device
adb install -r .p102tmp/p102-emulator-only.apk
adb logcat -c
adb shell am force-stop com.dsh.p102.trustedtoolprobe || true
adb shell am start -n com.dsh.p102.trustedtoolprobe/.P102FixtureActivity
probe(){
  adb logcat -d -v brief -s P102_TOOL_BINDER:I AndroidRuntime:E '*:S' \
    | sed -E 's/(session|grant|token)=[^ ]+/\1=[REDACTED]/g' \
    > .p102tmp/filtered-log.txt
  grep -Fq "$1" .p102tmp/filtered-log.txt
}
for i in $(seq 1 35);do
  if probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS';then break;fi
  if grep -Fq '=FAIL' .p102tmp/filtered-log.txt;then
    echo 'P102_PREGRANT_SECURITY_FAIL';exit 1
  fi
  sleep 1
done
probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
  echo 'P102_PREGRANT_NOT_OBSERVED';exit 1;
}
if grep -Fq 'P102_TRUSTED_EXECUTION_COUNT=' .p102tmp/filtered-log.txt;then
  echo 'P102_EXECUTED_BEFORE_NATIVE_APPROVAL=FAIL';exit 1
fi
if grep -Fq 'P102_TERMINAL_TOOL_RESULT=PASS' .p102tmp/filtered-log.txt;then
  echo 'P102_TERMINAL_BEFORE_NATIVE_APPROVAL=FAIL';exit 1
fi
echo 'P102_REAL_BINDER_PREGRANT_NO_EXECUTION=PASS'
SIZE="$(adb shell wm size | tr -d '\r' | tail -n1)"
COORDS="$(P102_SCREEN_SIZE="$SIZE" python3 - <<'PY'
import os,re
m=re.search(r'(\d{3,5})x(\d{3,5})',os.environ['P102_SCREEN_SIZE'])
if not m:raise SystemExit('P102_SCREEN_DIMENSIONS_UNKNOWN')
w,h=map(int,m.groups())
if w<320 or h<500:raise SystemExit('P102_SCREEN_DIMENSIONS_INVALID')
print(w//2,h//2)
PY
)"
read -r X Y <<< "$COORDS"
adb shell input tap "$X" "$Y"
for i in $(seq 1 35);do
  if probe 'P102_REAL_BINDER_NATIVE_TOOL_E2E=PASS';then break;fi
  if grep -Fq '=FAIL' .p102tmp/filtered-log.txt;then
    echo 'P102_RUNTIME_SECURITY_FAIL'
    grep 'P102_' .p102tmp/filtered-log.txt | tail -n 35 || true
    exit 1
  fi
  sleep 1
done
for marker in \
  'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' \
  'P102_PREAPPROVAL_REQUEST_GATE=PASS' \
  'P102_NATIVE_UI_APPROVAL_DISPATCH=YES' \
  'P102_TRUSTED_EXECUTION_COUNT=1' \
  'P102_TERMINAL_TOOL_RESULT=PASS' \
  'P102_REPLAY_REQUEST_DENIED=PASS' \
  'P102_REAL_BINDER_NATIVE_TOOL_E2E=PASS' \
  'P102_ORIGINAL_DSH_NODE_CONNECTED=NO';do
  if ! probe "$marker";then
    echo "P102_MISSING_REAL_BINDER_MARKER=$marker"
    grep 'P102_' .p102tmp/filtered-log.txt | tail -n 35 || true
    exit 1
  fi
done
if grep -Fq 'P102_TRUSTED_EXECUTION_COUNT=2' .p102tmp/filtered-log.txt;then
  echo 'P102_REPLAY_EXECUTED=FAIL';exit 1
fi
adb shell input keyevent HOME
for i in $(seq 1 12);do
  if probe 'P102_NATIVE_BACKGROUND_REVOKE=PASS';then break;fi
  sleep 1
done
probe 'P102_NATIVE_BACKGROUND_REVOKE=PASS' || {
  echo 'P102_BACKGROUND_REVOKE_NOT_OBSERVED';exit 1;
}
{
  echo 'P102_REAL_ANDROID35_FRAMEWORK_SENDING_UID=PASS'
  echo 'P102_REAL_ANDROID_NATIVE_UI_PREGRANT_DENY=PASS'
  echo 'P102_REAL_ANDROID_TOOL_EXACTLY_ONCE_REPLAY_DENY=PASS'
  echo 'P102_REAL_ANDROID_BACKGROUND_REVOKE=PASS'
  echo 'P102_ORIGINAL_DSH_NODE_TOOL_BINDER=NOT_WIRED'
} >> "$GITHUB_STEP_SUMMARY"
