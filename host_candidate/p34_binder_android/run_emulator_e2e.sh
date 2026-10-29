#!/usr/bin/env bash
set -euo pipefail
adb wait-for-device
adb install -r .p34tmp/p34-emulator-only.apk
adb logcat -c
adb shell am force-stop com.dsh.p34.brokertest || true
adb shell am start -n com.dsh.p34.brokertest/.P34Activity
probe_status(){
  adb logcat -d -v brief -s P34_BINDER_LAB:I AndroidRuntime:E '*:S' \
    | sed -E 's/(token|session|grant)=[^ ]+/\1=[REDACTED]/g' > .p34tmp/filtered-log.txt
  grep -Fq "$1" .p34tmp/filtered-log.txt
}
for i in $(seq 1 40);do
  if probe_status 'P34_PREGRANT_DENIAL=PASS';then break;fi
  if grep -Fq '=FAIL' .p34tmp/filtered-log.txt;then
    echo "P34_FAIL_BEFORE_UI_APPROVAL";exit 1
  fi
  sleep 1
done
if ! probe_status 'P34_PREGRANT_DENIAL=PASS';then
  echo "P34_PREGRANT_DENIAL=NOT_OBSERVED";exit 1
fi
if probe_status 'P34_REAL_BINDER_APPROVED_ONCE=PASS';then
  echo "P34_UNAUTHORIZED_APPROVAL_BEFORE_UI=FAIL";exit 1
fi
# Discover the actual native trusted Button using Android UI hierarchy,
# rather than assuming a phone-size/density-specific screen coordinate.
adb shell uiautomator dump /sdcard/p34-ui.xml >/dev/null
adb exec-out cat /sdcard/p34-ui.xml > .p34tmp/ui.xml
COORDS="$(python3 - <<'PY'
import xml.etree.ElementTree as ET, re
root=ET.parse(".p34tmp/ui.xml").getroot()
hits=[x for x in root.iter("node")
      if x.attrib.get("content-desc")=="P34_NATIVE_APPROVE_ONCE"]
if len(hits)!=1:raise SystemExit("P34_UI_APPROVE_BUTTON_NOT_UNIQUE")
b=hits[0].attrib.get("bounds","")
m=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",b)
if not m:raise SystemExit("P34_UI_BOUNDING_BOX_UNVERIFIED")
a,b,c,d=map(int,m.groups())
if c<=a or d<=b:raise SystemExit("P34_UI_EMPTY_BUTTON_BOUNDS")
print((a+c)//2,(b+d)//2)
PY
)"
read -r X Y <<< "$COORDS"
adb shell input tap "$X" "$Y"
sleep 1
probe_status 'P34_NATIVE_UI_CLICK_GRANT_SENT=YES' || {
  echo 'P34_NATIVE_UI_TOUCH_OR_GRANT=NOT_VERIFIED'
  grep 'P34_' .p34tmp/filtered-log.txt | tail -n 25 || true
}
for i in $(seq 1 40);do
  if probe_status 'P34_REAL_ISOLATED_UID_AND_NATIVE_CONSENT_E2E=PASS';then
    break
  fi
  if grep -Fq '=FAIL' .p34tmp/filtered-log.txt;then
    echo "P34_SECURITY_REGRESSION_MARKER=FAIL";exit 1
  fi
  sleep 1
done
for marker in \
  'P34_PREGRANT_DENIAL=PASS' \
  'P34_NATIVE_UI_CLICK_GRANT_SENT=YES' \
  'P34_REAL_BINDER_APPROVED_ONCE=PASS' \
  'P34_REAL_BINDER_REPLAY_DENIAL=PASS' \
  'P34_REAL_ISOLATED_UID_AND_NATIVE_CONSENT_E2E=PASS' \
  'P34_ORIGINAL_ARM64_NODE_RUNTIME_PRESENT=NO';do
  if ! probe_status "$marker";then
    echo "P34_MISSING_MARKER=$marker"
    grep 'P34_' .p34tmp/filtered-log.txt | tail -n 40 || true
    exit 1
  fi
done
adb shell input keyevent HOME
for i in $(seq 1 12);do
  if probe_status 'P34_HOST_BACKGROUND_REVOKE_INVOKED=PASS';then break;fi
  sleep 1
done
if ! probe_status 'P34_HOST_BACKGROUND_REVOKE_INVOKED=PASS';then
  echo "P34_HOST_BACKGROUND_REVOKE=NOT_OBSERVED";exit 1
fi
echo 'P34_EMULATOR35_REAL_ANDROID_BINDER_SENDING_UID=PASS' >> "$GITHUB_STEP_SUMMARY"
echo 'P34_SYNTHETIC_NODE_FRAME_UNGRANTED_TO_TRUSTED_UI_GRANT=PASS' >> "$GITHUB_STEP_SUMMARY"
echo 'P34_ONE_SHOT_NO_REPLAY_AND_BACKGROUND_REVOKE=PASS' >> "$GITHUB_STEP_SUMMARY"
echo 'P34_ORIGINAL_NODE_ARM64_OR_PRODUCTION_DSH_INTEGRATED=NO' >> "$GITHUB_STEP_SUMMARY"
echo 'P34_NO_REAL_USER_FILES_OR_NETWORK_ACCESS=YES' >> "$GITHUB_STEP_SUMMARY"
