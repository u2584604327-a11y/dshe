#!/usr/bin/env bash
set -euo pipefail
adb install --no-streaming out/p17-disposable.apk
adb logcat -c
adb shell am start -n com.dsh.p17.probe/.P17BrokerProbeActivity
sleep 4
# Use the actual Android UI hierarchy to locate the test-only user gesture.
# Never approximate display density or click arbitrary screen locations.
adb shell uiautomator dump /sdcard/p17-ui-test.xml >/dev/null
adb exec-out cat /sdcard/p17-ui-test.xml > out/p17-ui-test.xml
read -r tapx tapy < <(python3 - <<'PY'
import re,xml.etree.ElementTree as ET
root=ET.parse("out/p17-ui-test.xml").getroot()
found=[n for n in root.iter("node") if n.attrib.get("text")=="批准一次计数" and n.attrib.get("enabled")=="true"]
if len(found)!=1:raise SystemExit("P17_TRUSTED_UI_BUTTON_NOT_FOUND")
m=re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",found[0].attrib.get("bounds",""))
if not m:raise SystemExit("P17_UI_BOUNDS_MISSING")
x1,y1,x2,y2=map(int,m.groups())
if not(x2>x1 and y2>y1):raise SystemExit("P17_BAD_BUTTON_BOUNDS")
print((x1+x2)//2,(y1+y2)//2)
PY
)
adb shell input tap "$tapx" "$tapy"
adb shell rm -f /sdcard/p17-ui-test.xml
rm -f out/p17-ui-test.xml
sleep 8
adb logcat -d -s DSH_P17_BROKER:I '*:S' > out/p17-private-log.txt
for marker in \
 'P17_REAL_BINDER_UID=PASS' \
 'P17_PREGRANT_DENIED=PASS' \
 'P17_TRUSTED_UI_GRANT=PASS' \
 'P17_ONE_SHOT_APPROVED=PASS' \
 'P17_REPLAY_DENIED=PASS' \
 'P17_ARBITRARY_FILE_SCOPE_DENIED=PASS' \
 'P17_DSH_NODE_MIGRATED=NO'; do
  if ! grep -Fq "$marker" out/p17-private-log.txt; then
    echo "::error::P17 real Binder broker violation; expected fixed marker $marker"
    exit 1
  fi
done
if grep -Eq 'P17_.*=FAIL' out/p17-private-log.txt; then
  echo '::error::P17 unexpected broker failure'
  exit 1
fi
echo 'P17_BINDER_SENDING_UID_ISOLATED=PASS_ANDROID35' >> "$GITHUB_STEP_SUMMARY"
echo 'P17_HOST_UI_EXPLICIT_GRANT=PASS_ANDROID35' >> "$GITHUB_STEP_SUMMARY"
echo 'P17_ONE_SHOT_REPLAY_AND_RAW_FILE_DENIAL=PASS_ANDROID35' >> "$GITHUB_STEP_SUMMARY"
echo 'P17_DSH_NODE_ACTUAL_ISOLATED_MIGRATION=NO' >> "$GITHUB_STEP_SUMMARY"
