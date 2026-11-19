#!/usr/bin/env bash
# P200 disposable Android35 original-v138-derived pre-MainActivity observer.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
[[ -s "$apk" && -n "$ANDROID_HOME" ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
preexisting="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$preexisting" != *"package:com.dsh.android"* ]] || {
  echo P200_EXISTING_PHONE_DATA_OR_APP=DENY;exit 2;
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
if adb -s "$serial" install "$apk" >/dev/null 2>&1;then :;else
  echo P200_DISPOSABLE_APK_INSTALL=DENY;exit 2;
fi
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || {
  echo P200_FRESH_ORIGINAL_APP_UID=DENY;exit 2;
}
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P200_FRESH_ORIGINAL_DERIVED_PACKAGE_NO_EXTERNAL_EGRESS=PASS
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ -n "$launch" && "$launch" != com.dsh.android.p43.P43ProbeActivity ]] || {
  echo P200_ORIGINAL_MAIN_LAUNCHER_NOT_RESOLVED=DENY;exit 2;
}

# Ensure logcat acceptance begins BEFORE launching the test-only observer and
# before launching the untouched original MainActivity.
marker="P200_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P200_BOUNDARY_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P200_BOUNDARY "$marker" >/dev/null
status="$(adb -s "$serial" shell am start -W -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p200_prelaunch_window true)"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P200_BEFORE_MAIN_TEST_ACTIVITY=DENY;exit 2;
}
pid_before="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid_before" =~ ^[0-9]+$ ]] || {
  echo P200_NO_TEST_PROCESS_BEFORE_MAIN=DENY;exit 2;
}

selected=
read_markers(){
  local raw
  raw="$(adb -s "$serial" logcat -d -v brief \
    -s P200_BOUNDARY:I P200_PRELAUNCH:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v marker="$marker" '
    index($0,marker){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P200_INVALID_RUN_BOUNDARY"}')"
}
denied(){
  if [[ "$selected" == *"P200_"*"=DENY"* ]];then
    for name in P200_DISPOSABLE_HOST_REQUIREMENT \
      P200_DUPLICATE_PRELAUNCH_OBSERVER P200_ORIGINAL_LAUNCHER_UNRESOLVED \
      P200_OWNER_ACTIVITY_OR_UID_PID_CHANGED P200_STACK_COUNTER_REWOUND \
      P200_ENGINE_SINGLETON_REPLACED P200_UNEXPECTED_STATE_CATEGORY \
      P200_PRELAUNCH_OWNER_REVOKED P200_ORIGINAL_LAUNCHER_DUPLICATE_CREATE \
      P200_ORIGINAL_RESUME_WITHOUT_CREATE P200_ORIGINAL_DUPLICATE_RESUME \
      P200_PASSIVE_SAMPLES_INCOMPLETE P200_TEST_OWNER_DESTROYED \
      P200_ORIGINAL_LAUNCHER_DESTROYED_BEFORE_RESUME;do
      if [[ "$selected" == *"$name=DENY"* ]];then
        echo "P200_REDACTED_DENIAL_$name=DENY"
      fi
    done
    echo P200_REAL_ANDROID_LIFECYCLE_REJECTED=DENY
    exit 2
  fi
}

baseline=NO
for _ in $(seq 1 22);do
  read_markers
  if [[ "$selected" == *P200_INVALID_RUN_BOUNDARY* ]];then sleep 1;continue;fi
  denied
  if [[ "$selected" == *P200_BEFORE_ORIGINAL_LAUNCH=PASS* &&
        "$selected" == *P200_PRELAUNCH_BASELINE_BEFORE_MAIN_ACTIVITY=PASS* &&
        "$selected" == *P200_PRELAUNCH_ACTUAL_HOST_UID_PID=PASS* &&
        "$selected" == *P200_NO_ORIGINAL_ENGINE_START_OR_NODE_INVOKED=PASS* ]];then
    baseline=YES;break
  fi
  sleep 1
done
[[ "$baseline" == YES ]] || {
  echo P200_PRELAUNCH_BASELINE_MISSING=DENY;exit 2;
}
# First time launching the actual original MainActivity: prelaunch P150
# baseline and Application.ActivityLifecycleCallbacks already exist.
echo P200_BEFORE_MAIN_ACTIVITY_PRELAUNCH_BASELINE=PASS
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P200_ORIGINAL_MAIN_ACTIVITY_LAUNCH=DENY;exit 2;
}
pid_after="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid_after" == "$pid_before" ]] || {
  echo P200_ORIGINAL_MAIN_ACTIVITY_PROCESS_RESTART=DENY;exit 2;
}
echo P200_ORIGINAL_MAIN_AFTER_BASELINE_SAME_PROCESS=PASS

complete=NO
for _ in $(seq 1 30);do
  read_markers
  if [[ "$selected" == *P200_INVALID_RUN_BOUNDARY* ]];then sleep 1;continue;fi
  denied
  if [[ "$selected" == *P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONCREATE=PASS* &&
        "$selected" == *P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONRESUME=PASS* &&
        "$selected" == *P200_AFTER_ORIGINAL_ONCREATE=PASS* &&
        "$selected" == *P200_AFTER_ORIGINAL_ONRESUME=PASS* &&
        "$selected" == *P200_POST_RESUME_T0S=PASS* &&
        "$selected" == *P200_POST_RESUME_T2S=PASS* &&
        "$selected" == *P200_POST_RESUME_T5S=PASS* &&
        "$selected" == *P200_POST_RESUME_T10S=PASS* &&
        "$selected" == *P200_FOUR_POST_RESUME_PASSIVE_SAMPLES=PASS* &&
        "$selected" == *P200_OS_COROUTINE_PROVENANCE=NOT_ATTESTED* &&
        "$selected" == *P200_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED* &&
        "$selected" == *P200_SYNTHETIC_P43_BRIDGE=NOT_INVOKED* ]];then
    complete=YES;break
  fi
  sleep 1
done
if [[ "$complete" != YES ]];then
  for name in P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONCREATE \
    P200_ORIGINAL_LAUNCHER_FRAMEWORK_ONRESUME P200_AFTER_ORIGINAL_ONCREATE \
    P200_AFTER_ORIGINAL_ONRESUME P200_POST_RESUME_T0S \
    P200_POST_RESUME_T2S P200_POST_RESUME_T5S P200_POST_RESUME_T10S \
    P200_FOUR_POST_RESUME_PASSIVE_SAMPLES;do
    if [[ "$selected" != *"$name=PASS"* ]];then
      echo "P200_MISSING_REQUIRED_$name"
    fi
  done
  echo P200_REAL_ORIGINAL_MAIN_WINDOW_INCOMPLETE=DENY;exit 2
fi
if [[ "$selected" == *P200_ORIGINAL_START_PRELAUNCH_TO_10S=OBSERVED_NON_AUTHORITATIVE* ]];then
  echo P200_ORIGINAL_START_PRELAUNCH_TO_10S=OBSERVED_NON_AUTHORITATIVE
elif [[ "$selected" == *P200_ORIGINAL_START_PRELAUNCH_TO_10S=NOT_OBSERVED* ]];then
  echo P200_ORIGINAL_START_PRELAUNCH_TO_10S=NOT_OBSERVED
else
  echo P200_COROUTINE_ORIGIN_CLASSIFICATION_MISSING=DENY;exit 2
fi
echo P200_ACTUAL_ORIGINAL_MAIN_ACTIVITY_FRAMEWORK_CREATED_RESUMED=PASS
echo P200_PRE_MAIN_BASELINE_TO_REAL_ONRESUME_AND_FOUR_SAMPLES=PASS
echo P200_REAL_COROUTINE_OS_PROVENANCE=NOT_ATTESTED
echo P200_ACTUAL_PROCESS_READER_LATCH_STATEFLOW=NOT_ATTESTED
echo P200_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P200_V139=STRUCTURAL_BLOCKED
