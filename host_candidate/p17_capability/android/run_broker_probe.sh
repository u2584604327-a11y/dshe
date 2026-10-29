#!/usr/bin/env bash
set -euo pipefail
adb install --no-streaming out/p17-disposable.apk
adb logcat -c
adb shell am start -n com.dsh.p17.probe/.P17BrokerProbeActivity
sleep 4
# Explicit test-only simulated UI touch; never grant by process startup.
adb shell input tap 150 175
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
