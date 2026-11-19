#!/usr/bin/env bash
# P220 second fresh disposable Android35 trial; never user's installed DSH.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
original=.p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk
[[ -s "$apk" && -s "$original" && -n "${ANDROID_HOME:-}" ]]
[[ "$(sha256sum "$original" | cut -d' ' -f1)" == 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5 ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ "$launch" == com.dsh.android.MainActivity ]]
# Read-only pinned original vs offline test APK eligibility; unsupported
# profiling must not be repeatedly attempted or misread as no Node call.
policy="$(python3 -B host_candidate/p209_original_p47_deny/p221_profile_manifest_policy.py "$original" "$apk")" || {
 echo P221_MANIFEST_POLICY_PRECHECK=DENY;exit 2;
}
printf '%s\n' "$policy"
[[ "$policy" == *P221_SIGNED_AND_DISPOSABLE_MANIFEST_POLICY_AUDIT=PASS* ]] || {
 echo P221_MISSING_MANIFEST_POLICY_PROOF=DENY;exit 2;
}
# Only a manifest-only differently signed temporary APK is profileable;
# the signed original and baseline P209 APK remain immutable.
trap 'rm -rf -- .p222tmp' EXIT
if [[ "$policy" != *P221_DISPOSABLE_SHELL_PROFILE_ALLOWED=YES* ]];then
 if [[ "$P222_OFFLINE_PROFILE" != 1 ]];then
  echo P220_DISPOSABLE_TRACE=SKIPPED_UNPROFILEABLE_MANIFEST
  exit 0
 fi
 bash host_candidate/p209_original_p47_deny/p222_build_profileable_clone.sh
 apk=.p222tmp/P222-PROFILEABLE-OFFLINE-NOT-FOR-RELEASE.apk
 policy="$(python3 -B host_candidate/p209_original_p47_deny/p221_profile_manifest_policy.py "$original" "$apk")" || {
  echo P222_PROFILE_CLONE_POLICY=DENY;exit 2;
 }
 printf '%s\n' "$policy"
 [[ "$policy" == *P221_DISPOSABLE_DEBUGGABLE=NO* &&
    "$policy" == *P221_DISPOSABLE_SHELL_PROFILE_ALLOWED=YES* ]] || {
  echo P222_PROFILE_CLONE_UNEXPECTED_POLICY=DENY;exit 2;
 }
 echo P222_MANIFEST_ONLY_EMULATOR_CLONE=PASS
fi
already="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$already" != *"package:com.dsh.android"* ]] || {
 echo P220_PREEXISTING_PACKAGE_OR_DATA=DENY;exit 2;
}
umask 077
tmp="$(mktemp -d .p220-trace.XXXXXXXX)"
remote=/data/local/tmp/p220-dsh-test-only.trace
remote2=/data/local/tmp/p223-disposable-explicit-profile.trace
startpid=
uid=
cleanup(){
 adb -s "$serial" shell am profile stop com.dsh.android >/dev/null 2>&1 || true
 adb -s "$serial" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
 if [[ -n "$uid" ]];then
  adb -s "$serial" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
  adb -s "$serial" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
 fi
 adb -s "$serial" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
 adb -s "$serial" shell rm -f "$remote" "$remote2" >/dev/null 2>&1 || true
 rm -rf -- "$tmp" .p222tmp
}
trap cleanup EXIT
adb -s "$serial" shell test ! -e "$remote" || { echo P220_TRACE_ALREADY_EXISTS=DENY;exit 2; }
adb -s "$serial" shell test ! -e "$remote2" || { echo P223_PREEXISTING_SECOND_TRACE=DENY;exit 2; }
adb -s "$serial" install "$apk" >/dev/null
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || { echo P220_UID=DENY;exit 2; }
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P220_OFFLINE_IPV4_IPV6_OWNER_REJECT=PASS
# Only on disposable root QEMU: isolate event-buffer hints from the earlier
# fully completed P209 baseline (already copied to its own final raw log).
adb -s "$serial" logcat -b events -c >/dev/null 2>&1 || {
 echo P224_DISPOSABLE_EVENT_BUFFER_BOUNDARY=NOT_ATTESTED
}
echo P224_NO_USER_DEVICE_OR_ACCOUNT_EVENT_COLLECTION=YES
# AOSP am startup profiler uses method trace; no signed DEX instructions changed.
if ! status="$(adb -s "$serial" shell am start -W --start-profiler "$remote" --sampling 1000 -n "com.dsh.android/$launch" 2>/dev/null)";then
 echo P220_STARTUP_PROFILER=NOT_ATTESTED;exit 0
fi
if [[ ! "$status" =~ Status:\ (ok|warning) ]];then
 echo P220_STARTUP_PROFILER=NOT_ATTESTED;exit 0
fi
echo P220_PROFILED_FRESH_MAIN_START=PASS
startpid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n' || true)"
if [[ "$startpid" =~ ^[1-9][0-9]{1,7}$ ]];then
 echo P223_INITIAL_CLONE_HOST_PROCESS=OBSERVED
else
 echo P223_INITIAL_CLONE_HOST_PROCESS=NOT_ATTESTED
fi
sleep 12
# Capture immutable observation BEFORE the profiler stop; this distinguishes
# an in-session exit from a later stop-triggered PID change.
before_stop_pid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n' || true)"
if [[ "$startpid" =~ ^[1-9][0-9]{1,7}$ &&
      "$before_stop_pid" =~ ^[1-9][0-9]{1,7}$ ]];then
 if [[ "$startpid" == "$before_stop_pid" ]];then
  echo P224_PROCESS_PRE_STOP=STABLE
 else
  echo P224_PROCESS_PRE_STOP=CHANGED
 fi
else
 echo P224_PROCESS_PRE_STOP=NOT_ATTESTED
fi
if ! adb -s "$serial" shell am profile stop com.dsh.android >/dev/null 2>&1;then
 echo P220_PROFILE_STOP=NOT_ATTESTED;exit 0
fi
if ! adb -s "$serial" pull "$remote" "$tmp/trace.bin" >/dev/null 2>&1;then
 echo P220_TRACE_TRANSFER=NOT_ATTESTED;exit 0
fi
if python3 -B host_candidate/p209_original_p47_deny/p220_trace_parser.py "$tmp/trace.bin" | tee "$tmp/startup-allowlist.log";then
 echo P220_OFFLINE_ALLOWLIST_TRACE=PASS
else
 echo P220_OFFLINE_ALLOWLIST_TRACE=NOT_ATTESTED
fi
# Reuse the post-stop PID snapshot below for P224. No names or PIDs printed.
# P223: strictly supplemental method-profiling diagnostic. Never launch
# another Activity, invoke the Node engine or change original DEX/permissions.
# Check that a single host process survives; a changed PID cannot be treated
# as one continuous profiler session.
latepid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n' || true)"
if [[ "$before_stop_pid" =~ ^[1-9][0-9]{1,7}$ &&
      "$latepid" =~ ^[1-9][0-9]{1,7}$ ]];then
 if [[ "$before_stop_pid" == "$latepid" ]];then
  echo P224_PROCESS_AFTER_STOP=STABLE
 else
  echo P224_PROCESS_AFTER_STOP=CHANGED
 fi
else
 echo P224_PROCESS_AFTER_STOP=NOT_ATTESTED
fi
if [[ "$startpid" =~ ^[1-9][0-9]{1,7}$ &&
      "$latepid" =~ ^[1-9][0-9]{1,7}$ &&
      "$startpid" != "$latepid" ]];then
 if adb -s "$serial" logcat -b events -d -t 500 -v threadtime \
        -s am_proc_start:I am_proc_died:I am_crash:I am_anr:I am_kill:I '*:S' 2>/dev/null \
        | python3 -B host_candidate/p209_original_p47_deny/p224_event_hint_sanitize.py "$startpid" "$latepid";then
  echo P224_EVENT_HINT_COLLECTION=PASS
 else
  echo P224_EVENT_HINT_COLLECTION=NOT_ATTESTED
 fi
fi
if [[ ! "$startpid" =~ ^[1-9][0-9]{1,7}$ ||
      ! "$latepid" =~ ^[1-9][0-9]{1,7}$ ]];then
 echo P223_CLONE_PROCESS_CONTINUITY=NOT_ATTESTED
elif [[ "$latepid" != "$startpid" ]];then
 echo P223_CLONE_PROCESS_CONTINUITY=PID_CHANGED
else
 echo P223_CLONE_PROCESS_CONTINUITY=SAME_HOST_PID
 if adb -s "$serial" shell am profile start --sampling 1000 "$latepid" "$remote2" >/dev/null 2>&1;then
  echo P223_EXPLICIT_PROFILE_START=ACCEPTED
  sleep 6
  afterpid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n' || true)"
  if [[ "$afterpid" != "$latepid" ]];then
   echo P223_PROCESS_CHANGED_DURING_PROFILING=DENY
   adb -s "$serial" shell am profile stop "$latepid" >/dev/null 2>&1 || true
  elif adb -s "$serial" shell am profile stop "$latepid" >/dev/null 2>&1;then
   echo P223_EXPLICIT_PROFILE_STOP=ACCEPTED
   if adb -s "$serial" pull "$remote2" "$tmp/explicit.trace" >/dev/null 2>&1;then
    if python3 -B host_candidate/p209_original_p47_deny/p220_trace_parser.py "$tmp/explicit.trace" | tee "$tmp/explicit-allowlist.log";then
     echo P223_EXPLICIT_PROFILE_ALLOWLIST=PASS
    else
     echo P223_EXPLICIT_PROFILE_ALLOWLIST=NOT_ATTESTED
    fi
   else
    echo P223_EXPLICIT_PROFILE_TRACE_TRANSFER=NOT_ATTESTED
   fi
  else
   echo P223_EXPLICIT_PROFILE_STOP=NOT_ATTESTED
  fi
 else
  echo P223_EXPLICIT_PROFILE_START=NOT_ATTESTED
 fi
fi
# P226 is a FRESH temporary clone process, gated by the successfully parsed
# same-PID explicit trace, not by a lossy NODE_INSTALL sampling hit.
if [[ "$P226_OFFLINE_FULL_TRACE" == 1 &&
      "$P222_OFFLINE_PROFILE" == 1 &&
      "$apk" == .p222tmp/P222-PROFILEABLE-OFFLINE-NOT-FOR-RELEASE.apk &&
      -s "$tmp/explicit-allowlist.log" ]] &&
   grep -Fxq "P220_METHOD_TRACE_BINARY_VALIDATION=PASS" "$tmp/explicit-allowlist.log";then
 if bash host_candidate/p209_original_p47_deny/p226_nonsampling_disposable.sh "$apk" "$uid";then
  echo P226_EXTRA_NON_SAMPLED_DIAGNOSTIC=EXECUTED
 else
  echo P226_EXTRA_NON_SAMPLED_DIAGNOSTIC=NOT_ATTESTED
 fi
else
 echo P226_EXTRA_NON_SAMPLED_DIAGNOSTIC=SKIPPED_NO_VALID_EXPLICIT_TRACE
fi
echo P223_EXPLICIT_PROFILE_NOT_ORIGINAL_STARTUP_WITNESS=YES
echo P223_SAMPLING_MISS_IS_NOT_METHOD_ABSENCE=YES
echo P220_PROFILED_RUN_SEPARATE_FROM_P209_BASELINE=YES
echo P220_SIGNED_ORIGINAL_AND_USER_DATA_MODIFIED=NO
