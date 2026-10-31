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
# Do not guess that the centre of the physical screen is the Activity Button
# (Android 16 may have changed window insets, decorations or focus).
# Only click the explicit, *enabled*, original test native-approval button.
adb shell uiautomator dump /sdcard/p102-window.xml >/dev/null
COORDS="$(adb exec-out cat /sdcard/p102-window.xml | python3 -c '
import re,sys,xml.etree.ElementTree as ET
raw=sys.stdin.buffer.read(200001)
if len(raw)>200000:raise SystemExit("P102_UI_HIERARCHY_LIMIT")
root=ET.fromstring(raw)
buttons=[n for n in root.iter() if n.attrib.get("content-desc")=="P102_TRUSTED_NATIVE_APPROVAL"]
if len(buttons)!=1:raise SystemExit("P102_NATIVE_BUTTON_NOT_UNIQUE")
button=buttons[0]
if button.attrib.get("enabled")!="true":raise SystemExit("P102_NATIVE_BUTTON_NOT_ENABLED")
bounds=button.attrib.get("bounds","")
m=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",bounds)
if not m:raise SystemExit("P102_NATIVE_BUTTON_BOUNDS_INVALID")
a,b,c,d=map(int,m.groups())
if not(0<=a<c<=10000 and 0<=b<d<=10000):
    raise SystemExit("P102_NATIVE_BUTTON_RECT_INVALID")
print((a+c)//2,(b+d)//2)
')"
read -r X Y <<< "$COORDS"
echo 'P102_NATIVE_ENABLED_BUTTON_IDENTIFIED=PASS'
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
