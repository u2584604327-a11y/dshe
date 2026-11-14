#!/usr/bin/env bash
# P199 original-v138-derived disposable Android35 only, no third-party traffic.
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
  echo P199_PREEXISTING_USER_PACKAGE=DENY;exit 2;
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
  echo P199_EPHEMERAL_PACKAGE_INSTALL=DENY;exit 2;
fi
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || {
  echo P199_FRESH_ACTUAL_APP_UID=DENY;exit 2;
}
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P199_FRESH_ORIGINAL_DERIVED_APP_NO_EXTERNAL_EGRESS=PASS

launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ -n "$launch" && "$launch" != com.dsh.android.p43.P43ProbeActivity ]] || {
  echo P199_ORIGINAL_LAUNCHER_NOT_PRESERVED=DENY;exit 2;
}
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P199_ORIGINAL_LAUNCHER_START=DENY;exit 2;
}
sleep 3
pid_before="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid_before" =~ ^[0-9]+$ ]] || {
  echo P199_ORIGINAL_MAIN_PROCESS_NOT_ALIVE=DENY;exit 2;
}
echo P199_ORIGINAL_LAUNCHER_LAUNCHED_WITHOUT_P43_SYNTHETIC_BRIDGE=PASS
marker="P199_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P199_BOUNDARY_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P199_BOUNDARY "$marker" >/dev/null
status="$(adb -s "$serial" shell am start -W -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p199_passive_original true)"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P199_TEST_ONLY_PASSIVE_ACTIVITY_LAUNCH=DENY;exit 2;
}
pid_after="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid_after" == "$pid_before" ]] || {
  echo P199_ORIGINAL_HOST_PROCESS_GENERATION_CHANGED=DENY;exit 2;
}
echo P199_ORIGINAL_ACTIVITY_AND_TEST_OBSERVER_SAME_PROCESS=PASS

verified=NO
selected=
for _ in $(seq 1 25);do
  logs="$(adb -s "$serial" logcat -d -v brief \
    -s P199_BOUNDARY:I P199_PASSIVE:I '*:S')"
  selected="$(printf '%s\n' "$logs" | awk -v marker="$marker" '
    index($0,marker){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P199_INVALID_RUN_BOUNDARY"}')"
  if [[ "$selected" == *P199_INVALID_RUN_BOUNDARY* ]];then
    sleep 1;continue
  fi
  if [[ "$selected" == *"P199_"*"=DENY"* ]];then
    for code in P199_TEST_ONLY_HOST_PRECONDITION \
      P199_DUPLICATE_PASSIVE_PROBE P199_EXISTING_ORIGINAL_SINGLETON_MISSING \
      P199_OWNER_PROCESS_OR_ACTIVITY_CHANGED \
      P199_ORIGINAL_SINGLETON_POINTER_NOT_STABLE \
      P199_UNALLOWLISTED_ENGINE_STATE P199_STACK_COUNTER_NON_MONOTONIC \
      P199_MISSING_PASSIVE_SAMPLE; do
      if [[ "$selected" == *"$code=DENY"* ]];then
        echo "P199_SAFE_FAILURE_$code=DENY"
      fi
    done
    echo P199_REAL_ANDROID_PASSIVE_SECURITY_REJECTION=DENY;exit 2
  fi
  if [[ "$selected" == *P199_EXISTING_ORIGINAL_SINGLETON_AND_REAL_HOST_UID_PID=PASS* &&
        "$selected" == *P199_P43_SYNTHETIC_P40_BRIDGE=NOT_INVOKED* &&
        "$selected" == *P199_SAMPLE_0=PASS* &&
        "$selected" == *P199_SAMPLE_1=PASS* &&
        "$selected" == *P199_SAMPLE_2=PASS* &&
        "$selected" == *P199_SAMPLE_3=PASS* &&
        "$selected" == *P199_FOUR_BOUNDED_PASSIVE_SAMPLES=PASS* &&
        "$selected" == *P199_REAL_ORIGINAL_COROUTINE_OS_PROVENANCE=NOT_ATTESTED* &&
        "$selected" == *P199_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED* ]];then
    verified=YES;break
  fi
  sleep 1
done
if [[ "$verified" != YES ]];then
  for required in P199_EXISTING_ORIGINAL_SINGLETON_AND_REAL_HOST_UID_PID \
    P199_P43_SYNTHETIC_P40_BRIDGE P199_SAMPLE_0 P199_SAMPLE_1 \
    P199_SAMPLE_2 P199_SAMPLE_3 P199_FOUR_BOUNDED_PASSIVE_SAMPLES \
    P199_REAL_ORIGINAL_COROUTINE_OS_PROVENANCE;do
    if [[ "$selected" != *"$required="* ]];then
      echo "P199_MISSING_REQUIRED_MARKER_$required"
    fi
  done
  echo P199_REAL_ANDROID_PASSIVE_SAMPLES_INCOMPLETE=DENY;exit 2
fi
if [[ "$selected" == *P199_REAL_COROUTINE_STACK_SHAPE=OBSERVED_NON_AUTHORITATIVE* ]];then
  echo P199_REAL_COROUTINE_STACK_SHAPE=OBSERVED_NON_AUTHORITATIVE
elif [[ "$selected" == *P199_REAL_COROUTINE_STACK_SHAPE=NOT_OBSERVED* ]];then
  echo P199_REAL_COROUTINE_STACK_SHAPE=NOT_OBSERVED
else
  echo P199_UNCLASSIFIED_COROUTINE_OBSERVATION=DENY;exit 2
fi
echo P199_ORIGINAL_MAIN_ACTIVITY_NATURAL_LAUNCH=PASS
echo P199_FOUR_BOUNDED_REAL_ANDROID_PASSIVE_SAMPLES=PASS
echo P199_REAL_ORIGINAL_COROUTINE_OS_PROVENANCE=NOT_ATTESTED
echo P199_REAL_ENGINE_PROCESS_READER_LATCH_STATEFLOW_PARITY=NOT_ATTESTED
echo P199_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P199_V139=STRUCTURAL_BLOCKED
