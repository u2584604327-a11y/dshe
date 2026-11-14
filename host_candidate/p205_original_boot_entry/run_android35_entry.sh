#!/usr/bin/env bash
# P205 disposable Android35 true original MainActivity method-entry observation.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
[[ -s "$apk" && -n "${ANDROID_HOME:-}" ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
already="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$already" != *"package:com.dsh.android"* ]] || {
  echo P205_PREEXISTING_DSH_APP_OR_USER_DATA=DENY;exit 2;
}
uid=
cleanup(){
  adb -s "$serial" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
  if [[ -n "$uid" ]];then
    adb -s "$serial" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
    adb -s "$serial" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
  fi
  adb -s "$serial" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
}
trap cleanup EXIT
adb -s "$serial" install "$apk" >/dev/null || {
  echo P205_DISPOSABLE_APK_INSTALL_FAILED=DENY;exit 2;
}
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || {
  echo P205_FRESH_ACTUAL_HOST_UID=DENY;exit 2;
}
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P205_FRESH_TEST_PACKAGE_OUTBOUND_IPV4_IPV6_REJECT=PASS
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ "$launch" == com.dsh.android.MainActivity ]] || {
  echo P205_ORIGINAL_MAIN_LAUNCHER_CLASS_DRIFT=DENY;exit 2;
}
marker="P205_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P205_RUN_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P205_BOUNDARY "$marker" >/dev/null

# The original MainActivity is the FIRST activity opened by this app process.
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P205_ACTUAL_MAIN_ACTIVITY_COLD_START=DENY;exit 2;
}
pid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid" =~ ^[0-9]+$ ]] || {
  echo P205_ORIGINAL_MAIN_PROCESS_MISSING=DENY;exit 2;
}
echo P205_REAL_ANDROID_ORIGINAL_MANIFEST_MAINACTIVITY_LAUNCHED=PASS
echo P205_NO_SYNTHETIC_P43_BOOT_CALL=PASS
selected=
valid=NO
for _ in $(seq 1 18);do
  raw="$(adb -s "$serial" logcat -d -v threadtime \
    -s P205_BOUNDARY:I P205_ORIGINAL_ENTRY:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P205_INVALID_CURRENT_RUN_BOUNDARY"}')"
  if [[ "$selected" == *P205_INVALID_CURRENT_RUN_BOUNDARY* ]];then
    sleep 1;continue
  fi
  valid=YES
  if [[ "$selected" == *P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED* ]];then
    break
  fi
  sleep 1
done
[[ "$valid" == YES ]] || {
  echo P205_LOG_BOUNDARY_ORIGINAL_LAUNCH_NOT_ATTESTED=DENY;exit 2;
}
if [[ "$selected" == *P205_ORIGINAL_BOOTENGINE_ISOLATED_PROCESS=DENY* ]];then
  echo P205_REAL_METHOD_MARKER_ISOLATED_PROCESS=DENY;exit 2
fi
if [[ "$selected" == *P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED* ]];then
  count="$(printf '%s\n' "$selected" |
    grep -c 'P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED' || true)"
  # The test-only witness classifies the synchronous Java caller,
  # NOT the identity or lifecycle generation of the Activity instance.
  # The fixed-constant enum is read only after the unique current-run boundary.
  emit_fixed_caller(){
    local phase="$1" found=0 kind
    for kind in ONCREATE MAINACTIVITY_OTHER MAINACTIVITY_NESTED OTHER_OR_UNKNOWN UNAVAILABLE;do
      if [[ "$selected" == *"P205_ORIGINAL_BOOTENGINE_${phase}_CALLER=${kind}"* ]];then
        echo "P205_FIXED_${phase}_CALLER=${kind}"
        found=$((found+1))
      fi
    done
    [[ "$found" == 1 ]] || {
      echo "P205_${phase}_CALLER_CATEGORY_MISSING_OR_CONFLICT=DENY";return 2;
    }
  }
  emit_fixed_caller FIRST
  [[ "$count" == 1 ]] || {
    emit_fixed_caller SECOND
    echo P205_DUPLICATE_ORIGINAL_BOOTENGINE_ENTRY=DENY;exit 2;
  }
  truepid="$(printf '%s\n' "$selected" | awk -v pid="$pid" \
    'index($0,"P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED") &&
      $3==pid {n++} END{print n+0}')"
  [[ "$truepid" == 1 ]] || {
    echo P205_ORIGINAL_ENTRY_HOST_PROCESS_ID_DRIFT=DENY;exit 2;
  }
  echo P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=OBSERVED
else
  echo P205_ORIGINAL_BOOTENGINE_METHOD_ENTRY=NOT_OBSERVED
fi
echo P205_FIXED_SOURCE_REAL_MAINACTIVITY_LIFECYCLE=PASS
echo P205_ORIGINAL_BOOTENGINE_ENTRY_OBSERVATION_PROCEDURE=PASS
echo P205_ORIGINAL_INVOKESUSPEND_ENTRY=NOT_ATTESTED
echo P205_ACTUAL_ORIGINAL_PROCESS_READER_LATCH_STATEFLOW=NOT_ATTESTED
echo P205_REAL_OS_OWNER_EPOCH_P184_RECEIPT=NOT_WIRED
echo P205_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P205_V139=STRUCTURAL_BLOCKED
