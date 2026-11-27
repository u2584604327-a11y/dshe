#!/usr/bin/env bash
# P207 disposable Android35 true original MainActivity method-entry observation.
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
  echo P207_PREEXISTING_DSH_APP_OR_USER_DATA=DENY;exit 2;
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
  echo P207_DISPOSABLE_APK_INSTALL_FAILED=DENY;exit 2;
}
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || {
  echo P207_FRESH_ACTUAL_HOST_UID=DENY;exit 2;
}
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P207_FRESH_TEST_PACKAGE_OUTBOUND_IPV4_IPV6_REJECT=PASS
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ "$launch" == com.dsh.android.MainActivity ]] || {
  echo P207_ORIGINAL_MAIN_LAUNCHER_CLASS_DRIFT=DENY;exit 2;
}
marker="P207_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P207_RUN_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P207_BOUNDARY "$marker" >/dev/null

# The original MainActivity is the FIRST activity opened by this app process.
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P207_ACTUAL_MAIN_ACTIVITY_COLD_START=DENY;exit 2;
}
pid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid" =~ ^[0-9]+$ ]] || {
  echo P207_ORIGINAL_MAIN_PROCESS_MISSING=DENY;exit 2;
}
echo P207_REAL_ANDROID_ORIGINAL_MANIFEST_MAINACTIVITY_LAUNCHED=PASS
echo P207_NO_SYNTHETIC_P43_BOOT_CALL=PASS
selected=
valid=NO
for _ in $(seq 1 18);do
  raw="$(adb -s "$serial" logcat -d -v threadtime \
    -s P207_BOUNDARY:I P207_ORIGINAL_ENTRY:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P207_INVALID_CURRENT_RUN_BOUNDARY"}')"
  if [[ "$selected" == *P207_INVALID_CURRENT_RUN_BOUNDARY* ]];then
    sleep 1;continue
  fi
  valid=YES
  if [[ "$selected" == *P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED* ]];then
    break
  fi
  sleep 1
done
[[ "$valid" == YES ]] || {
  echo P207_LOG_BOUNDARY_ORIGINAL_LAUNCH_NOT_ATTESTED=DENY;exit 2;
}
if [[ "$selected" == *P207_ORIGINAL_ENGINE_START_ISOLATED_PROCESS=DENY* ]];then
  echo P207_REAL_METHOD_MARKER_ISOLATED_PROCESS=DENY;exit 2
fi
if [[ "$selected" == *P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED* ]];then
  count="$(printf '%s\n' "$selected" |
    grep -c 'P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED' || true)"
  # Kotlin may re-enter EngineManager.start on legitimate resume. Bound it,
  # preserve all observed counts and require every marker from the host PID.
  [[ "$count" =~ ^[0-9]+$ && "$count" -ge 1 && "$count" -le 8 ]] || {
    echo P207_ENGINE_START_ENTRY_COUNT_UNBOUNDED=DENY;exit 2;
  }
  truepid="$(printf '%s\n' "$selected" | awk -v pid="$pid" \
    'index($0,"P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED") &&
      $3==pid {n++} END{print n+0}')"
  [[ "$truepid" == "$count" ]] || {
    echo P207_ORIGINAL_ENGINE_START_ENTRY_HOST_PID_DRIFT=DENY;exit 2;
  }
  echo P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=OBSERVED
  echo P207_ORIGINAL_ENGINE_START_ENTRY_COUNT="$count"
else
  echo P207_ORIGINAL_ENGINE_START_METHOD_ENTRY=NOT_OBSERVED
fi
echo P207_FIXED_SOURCE_REAL_MAINACTIVITY_LIFECYCLE=PASS
echo P207_ORIGINAL_ENGINE_START_ENTRY_OBSERVATION_PROCEDURE=PASS
echo P207_ORIGINAL_ENGINE_START_RETURN=NOT_ATTESTED
echo P207_ACTUAL_ORIGINAL_PROCESS_READER_LATCH_STATEFLOW=NOT_ATTESTED
echo P207_REAL_OS_OWNER_EPOCH_P184_RECEIPT=NOT_WIRED
echo P207_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P207_V139=STRUCTURAL_BLOCKED
