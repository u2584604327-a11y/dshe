#!/usr/bin/env bash
set -euo pipefail
# P157: one E2E script, two independent emulator runners. Deny unknown API.
P102_ANDROID_API="${P102_ANDROID_API:-35}"
case "$P102_ANDROID_API" in 35|36) ;; *) echo P102_ANDROID_API_UNSUPPORTED=DENIED;exit 2;; esac
# P166: this runs INSIDE the Android emulator action, after its QEMU ELF is
# actually installed/booted. A closed loader is required before any consent.
if [[ "$P102_ANDROID_API" == 36 ]];then
  qemu_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
  qemu_binary="$qemu_root/emulator/qemu/linux-x86_64/qemu-system-x86_64"
  if [[ ! -x "$qemu_binary" ]];then
    echo P166_QEMU_POSTBOOT_ELF_UNAVAILABLE=FAIL;exit 1
  fi
  qemu_loader_report="$(ldd "$qemu_binary")" || {
    echo P166_QEMU_POSTBOOT_LDD=FAIL;exit 1
  }
  if grep -Fq '=> not found' <<< "$qemu_loader_report";then
    echo P166_QEMU_POSTBOOT_DEPENDENCY_MISSING=FAIL;exit 1
  fi
  echo P166_QEMU_POSTBOOT_FULL_LOADER_DEPENDENCIES=PASS
fi
# Isolate all ADB operations to the sole transient CI emulator serial.
# Never resolve to a connected physical or user Android device.
export ANDROID_SERIAL=emulator-5554
adb wait-for-device
source "$(dirname "$0")/p164_emulator_screen_preflight.sh"
p164_prepare_disposable_emulator_ui "$P102_ANDROID_API"
adb install -r .p102tmp/p102-emulator-only.apk
adb logcat -c
adb shell am force-stop com.dsh.p102.trustedtoolprobe || true
adb shell am start -n com.dsh.p102.trustedtoolprobe/.P102FixtureActivity
# Source pure lab-native consent gate; never approves on its own.
source "$(dirname "$0")/p102_native_focus_gate.sh"
p162_os_resumed_app(){
  # Read-only Android ActivityManager independent of fixture-reported rect.
  # Exact package AND Activity token must be the current top-resumed app.
  local current
  current="$(adb shell dumpsys activity activities 2>/dev/null |
    grep -E 'topResumedActivity=|mResumedActivity=' | head -n 8 || true)"
  grep -Eq 'com\.dsh\.p102\.trustedtoolprobe/.?P102FixtureActivity|com\.dsh\.p102\.trustedtoolprobe/com\.dsh\.p102\.trustedtoolprobe\.P102FixtureActivity' <<< "$current"
}
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
# Android 36 can transiently present an incomplete accessibility tree.
# Only re-read UI hierarchy. Never relaunch, guess tap coordinates or click
# multiple/disabled buttons. Unresolved ambiguity remains a hard failure.
COORDS=""
UI_LAST_REASON="NOT_OBSERVED"
for attempt in $(seq 1 35); do
  # The accessibility dumper can briefly alter Activity focus. A stale
  # enabled button from an earlier Binder session MUST NOT be clicked.
  # Snapshot the native revoke/pending event counts before inspecting UI.
  probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
    echo 'P102_PREAPPROVAL_MISSING_BEFORE_UI_DUMP=FAIL'; exit 1;
  }
  before_revoke="$(grep -Fc 'P102_NATIVE_BACKGROUND_REVOKE=PASS' .p102tmp/filtered-log.txt || true)"
  before_pending="$(grep -Fc 'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' .p102tmp/filtered-log.txt || true)"
  # P162: Android36 UiAutomator intermittently returns ONLY SystemUI nodes.
  # Instead require true native visible button rect AND OS top-resumed app
  # before any real input. No blind screen-center or repeated taps.
  if [[ "$P102_ANDROID_API" == 36 ]]; then
    if COORDS="$(python3 "$(dirname "$0")/p162_native_visible_rect.py" .p102tmp/filtered-log.txt 2> .p102tmp/ui-selection-reason.txt)";then
      after_revoke="$(grep -Fc 'P102_NATIVE_BACKGROUND_REVOKE=PASS' .p102tmp/filtered-log.txt || true)"
      after_pending="$(grep -Fc 'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' .p102tmp/filtered-log.txt || true)"
      sleep 1
      probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
        echo P162_PENDING_DISAPPEARED_DURING_FOCUS_SETTLE=FAIL;exit 1;
      }
      if p102_native_focus_gate .p102tmp/filtered-log.txt "$after_revoke" "$after_pending" &&
         p162_os_resumed_app;then
        UI_LAST_REASON="READY_NATIVE_VIEW_OS_FOCUS"
        echo P162_ANDROID36_NATIVE_VISIBLE_VIEW_AND_OS_RESUMED=PASS
        break
      fi
      UI_LAST_REASON="P162_NATIVE_VIEW_OR_OS_RESUME_UNSTABLE"
      COORDS=""
    else
      UI_LAST_REASON="$(head -n1 .p102tmp/ui-selection-reason.txt || true)"
      COORDS=""
    fi
    if grep -Fq 'P102_TRUSTED_EXECUTION_COUNT=' .p102tmp/filtered-log.txt;then
      echo P162_EXECUTED_BEFORE_VERIFIED_NATIVE_CLICK=FAIL;exit 1;
    fi
    sleep 1
    continue
  fi
  if ! adb shell uiautomator dump /sdcard/p102-window.xml >/dev/null 2>&1; then
    UI_LAST_REASON="UI_DUMP_UNAVAILABLE"
  else
    if COORDS="$(adb exec-out cat /sdcard/p102-window.xml | python3 -c '
import re,sys,xml.etree.ElementTree as ET
raw=sys.stdin.buffer.read(200001)
if len(raw)>200000:raise SystemExit("P102_UI_HIERARCHY_LIMIT")
try:root=ET.fromstring(raw)
except ET.ParseError:raise SystemExit("P102_UI_XML_TRANSIENT")
buttons=[n for n in root.iter() if n.attrib.get("content-desc")=="P102_TRUSTED_NATIVE_APPROVAL"]
if not buttons:raise SystemExit("P102_NATIVE_BUTTON_MISSING")
if len(buttons)>1:raise SystemExit("P102_NATIVE_BUTTON_DUPLICATE_COUNT_"+str(len(buttons)))
button=buttons[0]
if button.attrib.get("package")!="com.dsh.p102.trustedtoolprobe":
    raise SystemExit("P102_NATIVE_BUTTON_FOREIGN_PACKAGE")
if button.attrib.get("clickable")!="true":
    raise SystemExit("P102_NATIVE_BUTTON_NOT_CLICKABLE")
if button.attrib.get("enabled")!="true":raise SystemExit("P102_NATIVE_BUTTON_NOT_ENABLED")
bounds=button.attrib.get("bounds","")
m=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",bounds)
if not m:raise SystemExit("P102_NATIVE_BUTTON_BOUNDS_INVALID")
a,b,c,d=map(int,m.groups())
if not(0<=a<c<=10000 and 0<=b<d<=10000):
    raise SystemExit("P102_NATIVE_BUTTON_RECT_INVALID")
print((a+c)//2,(b+d)//2)
' 2> .p102tmp/ui-selection-reason.txt)"; then
      # Re-read native lifecycle markers AFTER the accessibility dump.
      # If onStop/rebind changed the pending Binder session while the XML
      # was captured, discard the coordinates and retry ONLY the read.
      probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
        echo 'P102_PREAPPROVAL_LOST_AFTER_UI_DUMP=FAIL'; exit 1;
      }
      after_revoke="$(grep -Fc 'P102_NATIVE_BACKGROUND_REVOKE=PASS' .p102tmp/filtered-log.txt || true)"
      after_pending="$(grep -Fc 'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' .p102tmp/filtered-log.txt || true)"
      last_lifecycle="$(grep -E 'P102_(NATIVE_BACKGROUND_REVOKE|REAL_BINDER_PENDING_NATIVE_APPROVAL)=PASS' .p102tmp/filtered-log.txt | tail -n1 || true)"
      if test "$before_revoke" != "$after_revoke" ||
         test "$before_pending" != "$after_pending" ||
         [[ "$last_lifecycle" != *'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS'* ]]; then
        UI_LAST_REASON="P102_UI_STALE_PENDING_OR_ACTIVITY_REVOKED"
        COORDS=""
      else
        # P161: after uiautomator returns, wait for Activity native focus to
        # recover. A stale coordinate must never be tapped during onStop
        # revoke/rebind or before a fresh exact pending Binder request.
        sleep 1
        probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
          echo 'P102_PREAPPROVAL_LOST_DURING_FOCUS_SETTLE=FAIL'; exit 1;
        }
        if p102_native_focus_gate .p102tmp/filtered-log.txt "$after_revoke" "$after_pending"; then
          UI_LAST_REASON="READY"
          break
        fi
        UI_LAST_REASON="P102_NATIVE_FOCUS_OR_PENDING_UNSTABLE"
        COORDS=""
      fi
    else
      UI_LAST_REASON="$(head -n1 .p102tmp/ui-selection-reason.txt || true)"
      COORDS=""
    fi
  fi
  probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
    echo 'P102_PREAPPROVAL_LOST_DURING_UI_POLL=FAIL'; exit 1;
  }
  if grep -Fq '=FAIL' .p102tmp/filtered-log.txt ||
     grep -Fq 'P102_TRUSTED_EXECUTION_COUNT=' .p102tmp/filtered-log.txt;then
    echo 'P102_UNEXPECTED_NATIVE_GATE_STATE_DURING_UI_POLL=FAIL'; exit 1
  fi
  sleep 1
done
if test -z "$COORDS";then
  echo "P102_NATIVE_BUTTON_UNAVAILABLE_AFTER_BOUNDED_POLL=${UI_LAST_REASON}"
  # Android emulator only: bounded, privacy-safe diagnostics of the failure.
  # Do NOT emit the full UI XML, text, screenshot, app data or accessibility
  # content of unrelated windows. Only count/identify the lab's own nodes.
  adb exec-out cat /sdcard/p102-window.xml 2>/dev/null | python3 -c '
import sys,xml.etree.ElementTree as ET
raw=sys.stdin.buffer.read(200001)
try:root=ET.fromstring(raw)
except (ET.ParseError,ValueError):
  print("P102_UI_DIAG_XML=UNAVAILABLE")
  sys.exit(0)
nodes=list(root.iter())
lab=[x for x in nodes if x.attrib.get("package")=="com.dsh.p102.trustedtoolprobe"]
exact=[x for x in nodes if x.attrib.get("content-desc")=="P102_TRUSTED_NATIVE_APPROVAL"]
enabled=[x for x in exact if x.attrib.get("enabled")=="true"]
print("P102_UI_DIAG_TOTAL_NODES="+str(len(nodes)))
print("P102_UI_DIAG_LAB_NODES="+str(len(lab)))
print("P102_UI_DIAG_EXACT_APPROVAL_NODES="+str(len(exact)))
print("P102_UI_DIAG_ENABLED_APPROVAL_NODES="+str(len(enabled)))
' || true
  # This read-only window summary never changes focus or calls am start.
  adb shell dumpsys activity activities 2>/dev/null |
    grep -E 'mResumedActivity=|topResumedActivity=|mFocusedApp=' |
    sed -E 's/.*(com\.dsh\.p102\.trustedtoolprobe|com\.android\.systemui|com\.android\.launcher[[:alnum:]_.]*).*/P102_UI_DIAG_FOCUS_PACKAGE=\1/' |
    grep '^P102_UI_DIAG_FOCUS_PACKAGE=' | head -n 3 || true
  # P164: distinguish foreground Activity from real native window focus.
  # Only count our own synthetic lab tag; no screenshots or raw UI content.
  probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || true
  for focus in YES NO;do
    echo "P164_UI_DIAG_NATIVE_WINDOW_FOCUS_${focus}=$(grep -Fc "P102_NATIVE_WINDOW_FOCUS=${focus}" .p102tmp/filtered-log.txt || true)"
  done
  echo "P164_UI_DIAG_VISIBLE_NATIVE_BUTTON_RECTS=$(grep -Fc 'P162_VISIBLE_NATIVE_APPROVAL_RECT=' .p102tmp/filtered-log.txt || true)"
  # Diagnostics are counts/categories from the lab-only log tag, never
  # original DSH chat, account data, model text, screenshots or raw UI XML.
  # Crucially, do not relaunch the Activity or attempt a blind approval.
  probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || true
  for spec in \
    'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' \
    'P102_NATIVE_BACKGROUND_REVOKE=PASS' \
    'P102_NATIVE_FOREGROUND_BIND=PASS' \
    'P102_REAL_SERVICE_BIND=FAIL' \
    'P102_TRUSTED_EXECUTION_COUNT=' \
    'P102_NATIVE_UI_APPROVAL_DISPATCH='; do
    count="$(grep -Fc "$spec" .p102tmp/filtered-log.txt || true)"
    key="${spec%%=*}"
    echo "P102_UI_DIAG_${key}=${count}"
  done
  latest="$(grep -Eo 'P102_(NATIVE_BACKGROUND_REVOKE|REAL_BINDER_PENDING_NATIVE_APPROVAL|NATIVE_FOREGROUND_BIND)=PASS' \
    .p102tmp/filtered-log.txt | tail -n 1 || true)"
  case "$latest" in
    P102_NATIVE_BACKGROUND_REVOKE=PASS) echo 'P102_UI_DIAG_LATEST_LIFECYCLE=REVOKED';;
    P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS) echo 'P102_UI_DIAG_LATEST_LIFECYCLE=PENDING';;
    P102_NATIVE_FOREGROUND_BIND=PASS) echo 'P102_UI_DIAG_LATEST_LIFECYCLE=BOUND_AWAITING_REQUEST';;
    *) echo 'P102_UI_DIAG_LATEST_LIFECYCLE=NOT_OBSERVED';;
  esac
  exit 1
fi
read -r X Y <<< "$COORDS"
# P161 final read-only, same-generation gate immediately before the ONE tap.
# If focus changed again, hard fail. Never blind-click or reattempt approval.
probe 'P102_PREAPPROVAL_REQUEST_GATE=PASS' || {
  echo P161_PRECLICK_PENDING_LOST=FAIL; exit 1;
}
if ! p102_native_focus_gate .p102tmp/filtered-log.txt "$after_revoke" "$after_pending";then
  echo P161_PRECLICK_FOCUS_OR_BINDER_GENERATION_STALE=FAIL
  exit 1
fi
if [[ "$P102_ANDROID_API" == 36 ]];then
  # Revalidate native rectangle freshness AND independent ActivityManager
  # top-resumed identity just before the single original UI button tap.
  if ! p162_os_resumed_app ||
     ! python3 "$(dirname "$0")/p162_native_visible_rect.py" .p102tmp/filtered-log.txt >/dev/null;then
    echo P162_PRECLICK_NATIVE_RECT_OR_OS_WINDOW_STALE=FAIL;exit 1
  fi
fi
echo 'P102_NATIVE_ENABLED_BUTTON_IDENTIFIED=PASS'
echo 'P161_NATIVE_FOCUS_AND_PENDING_GENERATION_VERIFIED_BEFORE_CLICK=PASS'
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
  'P102_HOST_WORKER_TERMINAL_RECEIPT=PASS_OBSERVATION_ONLY' \
  'P102_HOST_REPLAY_REQUEST_REJECTED=PASS' \
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
  echo "P102_REAL_ANDROID${P102_ANDROID_API}_FRAMEWORK_SENDING_UID=PASS"
  echo "P102_REAL_ANDROID${P102_ANDROID_API}_NATIVE_UI_PREGRANT_DENY=PASS"
  echo "P102_REAL_ANDROID${P102_ANDROID_API}_TOOL_EXACTLY_ONCE_REPLAY_DENY=PASS"
  echo "P102_REAL_ANDROID${P102_ANDROID_API}_BACKGROUND_REVOKE=PASS"
  echo 'P102_ORIGINAL_DSH_NODE_TOOL_BINDER=NOT_WIRED'
} >> "$GITHUB_STEP_SUMMARY"
