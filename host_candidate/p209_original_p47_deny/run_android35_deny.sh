#!/usr/bin/env bash
# P208 disposable Android35 true original MainActivity method-entry observation.
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
  echo P208_PREEXISTING_DSH_APP_OR_USER_DATA=DENY;exit 2;
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
  echo P208_DISPOSABLE_APK_INSTALL_FAILED=DENY;exit 2;
}
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || {
  echo P208_FRESH_ACTUAL_HOST_UID=DENY;exit 2;
}
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P208_FRESH_TEST_PACKAGE_OUTBOUND_IPV4_IPV6_REJECT=PASS
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ "$launch" == com.dsh.android.MainActivity ]] || {
  echo P208_ORIGINAL_MAIN_LAUNCHER_CLASS_DRIFT=DENY;exit 2;
}
marker="P208_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P208_RUN_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P208_BOUNDARY "$marker" >/dev/null

# The original MainActivity is the FIRST activity opened by this app process.
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]] || {
  echo P208_ACTUAL_MAIN_ACTIVITY_COLD_START=DENY;exit 2;
}
pid="$(adb -s "$serial" shell pidof com.dsh.android | tr -d '\r\n')"
[[ "$pid" =~ ^[0-9]+$ ]] || {
  echo P208_ORIGINAL_MAIN_PROCESS_MISSING=DENY;exit 2;
}
echo P208_REAL_ANDROID_ORIGINAL_MANIFEST_MAINACTIVITY_LAUNCHED=PASS
echo P208_NO_SYNTHETIC_P43_BOOT_CALL=PASS
selected=
valid=NO
for _ in $(seq 1 18);do
  raw="$(adb -s "$serial" logcat -d -v threadtime \
    -s P208_BOUNDARY:I P208_ORIGINAL_ENTRY:I P209_GATE:I P209_P40:I P209_PREP40:I P209_GUARD:I P209_FALL:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P208_INVALID_CURRENT_RUN_BOUNDARY"}')"
  if [[ "$selected" == *P208_INVALID_CURRENT_RUN_BOUNDARY* ]];then
    sleep 1;continue
  fi
  valid=YES
  if [[ "$selected" == *P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED* &&
        "$selected" == *P209_P47_FINAL_DENY_UID=* ]];then
    break
  fi
  sleep 1
done
[[ "$valid" == YES ]] || {
  echo P208_LOG_BOUNDARY_ORIGINAL_LAUNCH_NOT_ATTESTED=DENY;exit 2;
}
if [[ "$selected" == *P208_ORIGINAL_START2_INVOKESUSPEND_ISOLATED_PROCESS=DENY* ]];then
  echo P208_REAL_METHOD_MARKER_ISOLATED_PROCESS=DENY;exit 2
fi
if [[ "$selected" == *P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED* ]];then
  count="$(printf '%s\n' "$selected" |
    grep -c 'P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED' || true)"
  # Kotlin may re-enter invokeSuspend on legitimate resume. Bound it,
  # preserve all observed counts and require every marker from the host PID.
  [[ "$count" =~ ^[0-9]+$ && "$count" -ge 1 && "$count" -le 8 ]] || {
    echo P208_COROUTINE_ENTRY_COUNT_UNBOUNDED=DENY;exit 2;
  }
  truepid="$(printf '%s\n' "$selected" | awk -v pid="$pid" \
    'index($0,"P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED") &&
      $3==pid {n++} END{print n+0}')"
  [[ "$truepid" == "$count" ]] || {
    echo P208_ORIGINAL_COROUTINE_ENTRY_HOST_PID_DRIFT=DENY;exit 2;
  }
  echo P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED
  echo P208_ORIGINAL_START2_INVOKESUSPEND_RESUME_COUNT="$count"
  uids="$(printf '%s\n' "$selected" |
     awk -v pid="$pid" 'index($0,"P208_ORIGINAL_START2_COROUTINE_UID=") && $3==pid {
       n=split($0,a,"P208_ORIGINAL_START2_COROUTINE_UID="); if(n==2){x=a[2];sub(/[[:space:]].*/,"",x);print x}
     }')"
  count_uid="$(printf '%s\n' "$uids" | grep -c . || true)"
  [[ "$count_uid" == "$count" ]] || {
    echo P208_UID_WITNESS_COUNT_MISMATCH=DENY;exit 2;
  }
  if printf '%s\n' "$uids" | grep -vFxq "$uid";then
    echo P208_HOST_OS_UID_MISMATCH=DENY;exit 2;
  fi
  echo P208_ORIGINAL_START2_COROUTINE_HOST_PID_UID_MATCH=PASS
  if [[ "$selected" == *P209_PRE_P40_ISOLATED=DENY* ]];then
    echo P209_PRE_PC3912_MARKER_ISOLATED=DENY;exit 2
  fi
  precall_total="$(printf '%s\n' "$selected" | grep -Fc 'P209_PRE_P40_WITNESS=OBSERVED' || true)"
  precall_host="$(printf '%s\n' "$selected" | awk -v pid="$pid" '
    index($0,"P209_PRE_P40_WITNESS=OBSERVED") && $3==pid{n++}
    END{print n+0}')"
  [[ "$precall_total" == "$precall_host" ]] || {
    echo P209_PRE_PC3912_FOREIGN_PID=DENY;exit 2;
  }
  if [[ "$precall_host" -gt 0 ]];then
    echo P209_ORIGINAL_PC3912_PRE_P40=OBSERVED
  else
    echo P209_ORIGINAL_PC3912_PRE_P40=NOT_OBSERVED
  fi
else
  echo P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=NOT_OBSERVED
fi

# P209: same fresh original coroutine entry and P47 final DENY from actual host.
# P209 safe observation counters are scoped after this run's single unique log boundary.
# Never emit original runtime builder argv, env, UID numbers, stack traces or raw Logcat.
p209_count() {
  printf '%s\n' "$selected" | grep -Fc "$1" || true
}
p209_count_pid() {
  printf '%s\n' "$selected" | awk -v pid="$pid" -v k="$1" \
    'index($0,k) && $3==pid{n++} END{print n+0}'
}
p209_gate_diagnostic() {
  echo "P209_PC30_FALL_TAG_COUNT=$(p209_count 'P209_PC30_FALLTHROUGH=OBSERVED')"
  echo "P209_PC30_FALL_HOST_PID_COUNT=$(p209_count_pid 'P209_PC30_FALLTHROUGH=OBSERVED')"
  echo "P209_PC30_FALL_ISOLATED_COUNT=$(p209_count 'P209_PC30_FALL_ISOLATED=DENY')"
  echo "P209_FIRST_GUARD_TAG_COUNT=$(p209_count 'P209_FIRST_GUARD=OBSERVED')"
  echo "P209_FIRST_GUARD_HOST_PID_COUNT=$(p209_count_pid 'P209_FIRST_GUARD=OBSERVED')"
  echo "P209_FIRST_GUARD_ISOLATED_COUNT=$(p209_count 'P209_FIRST_GUARD_ISOLATED=DENY')"
  echo "P209_PRE_PC3912_TAG_COUNT=$(p209_count 'P209_PRE_P40_WITNESS=OBSERVED')"
  echo "P209_PRE_PC3912_HOST_PID_COUNT=$(p209_count_pid 'P209_PRE_P40_WITNESS=OBSERVED')"
  echo "P209_PRE_PC3912_ISOLATED_DENY_COUNT=$(p209_count 'P209_PRE_P40_ISOLATED=DENY')"
  echo "P209_P40_ENTRY_TAG_COUNT=$(p209_count 'P209_P40_BRIDGE_ENTRY=OBSERVED')"
  echo "P209_P40_ENTRY_HOST_PID_COUNT=$(p209_count_pid 'P209_P40_BRIDGE_ENTRY=OBSERVED')"
  echo "P209_GATE_ENTRY_TAG_COUNT=$(p209_count 'P209_P47_ENTER_UID=')"
  echo "P209_GATE_ENTRY_HOST_PID_COUNT=$(p209_count_pid 'P209_P47_ENTER_UID=')"
  echo "P209_GATE_FINAL_TAG_COUNT=$(p209_count 'P209_P47_FINAL_DENY_UID=')"
  echo "P209_GATE_FINAL_HOST_PID_COUNT=$(p209_count_pid 'P209_P47_FINAL_DENY_UID=')"
  echo "P209_GATE_ORIGINAL_STACK_PASS_COUNT=$(p209_count_pid 'P209_ORIGINAL_CALLSTACK=PASS')"
  echo "P209_GATE_ORIGINAL_STACK_OTHER_COUNT=$(p209_count_pid 'P209_ORIGINAL_CALLSTACK=OTHER')"
}
if [[ "$selected" == *P209_PC30_FALL_ISOLATED=DENY* ]];then
  echo P209_PC30_FALL_ISOLATED=DENY;exit 2
fi
if [[ "$selected" == *P209_FIRST_GUARD_ISOLATED=DENY* ]];then
  echo P209_FIRST_GUARD_ISOLATED_HOST=DENY;exit 2
fi
guard_total="$(p209_count 'P209_FIRST_GUARD=OBSERVED')"
guard_host="$(p209_count_pid 'P209_FIRST_GUARD=OBSERVED')"
[[ "$guard_total" == "$guard_host" ]] || {
  echo P209_FIRST_GUARD_FOREIGN_HOST_PID=DENY;exit 2
}
if [[ "$guard_host" -gt 0 ]];then
  echo P209_FIRST_GUARD=OBSERVED
else
  echo P209_FIRST_GUARD=NOT_OBSERVED
fi
fall_total="$(p209_count 'P209_PC30_FALLTHROUGH=OBSERVED')"
fall_host="$(p209_count_pid 'P209_PC30_FALLTHROUGH=OBSERVED')"
[[ "$fall_total" == "$fall_host" && "$fall_host" -le "$guard_host" ]] || {
  echo P209_PC30_FALL_FOREIGN_OR_UNMATCHED_GUARD=DENY;exit 2
}
if [[ "$fall_host" -gt 0 ]];then
  printf '%s\n' "$selected" | awk '
    /P209_FIRST_GUARD=OBSERVED/{if(!g)g=NR}
    /P209_PC30_FALLTHROUGH=OBSERVED/{if(!f)f=NR}
    END{if(!g||!f||f<=g)exit 2}' || {
    echo P209_PC26_PC30_EVENT_ORDER=DENY;exit 2
  }
  echo P209_PC26_FALLTHROUGH_TO_PC30=OBSERVED
else
  echo P209_PC26_FALLTHROUGH_TO_PC30=NOT_OBSERVED
fi
echo P209_PC26_TAKEN_PC176=NOT_DIRECTLY_ATTESTED
for key in P209_P47_ENTER_UID= P209_P47_FINAL_DENY_UID=;do
  vals="$(printf '%s\n' "$selected" | awk -v pid="$pid" -v key="$key" '
    index($0,key) && $3==pid {n=split($0,a,key);if(n==2){v=a[2];sub(/[[:space:]].*/,"",v);print v}}')"
  [[ "$(printf '%s\n' "$vals" | grep -c . || true)" == 1 &&
     "$vals" == "$uid" ]] || {
     p209_gate_diagnostic
     echo P209_GATE_OS_PID_UID_MISMATCH_OR_NOT_OBSERVED=DENY;exit 2;
  }
done
count="$(printf '%s\n' "$selected" | awk -v pid="$pid" '
   index($0,"P209_ORIGINAL_CALLSTACK=PASS") && $3==pid{n++} END{print n+0}')"
[[ "$count" == 1 ]] || { echo P209_ORIGINAL_P40_STACK_SHAPE_NOT_OBSERVED=DENY;exit 2; }
printf '%s\n' "$selected" | awk '
  /P208_ORIGINAL_START2_INVOKESUSPEND_METHOD_ENTRY=OBSERVED/{if(!entry)entry=NR}
  /P209_P47_ENTER_UID=/{if(!gate)gate=NR}
  /P209_P47_FINAL_DENY_UID=/{if(!denied)denied=NR}
  END {if(!(entry>0 && gate>entry && denied>gate))exit 2}' || {
   echo P209_REAL_ORIGINAL_COROUTINE_TO_FINAL_DENY_ORDER=DENY;exit 2;
  }
echo P209_REAL_ORIGINAL_START2_COROUTINE_TO_P47_GATE=PASS
echo P209_ORIGINAL_P47_FINAL_DENY_THROW_BRANCH=OBSERVED
echo P209_REAL_GATE_HOST_PID_UID_AND_EVENT_ORDER=PASS
echo P209_ORIGINAL_DENIED_LAUNCH_CHILD=NOT_CREATED_BY_P47
echo P209_ACTUAL_CHILD_OS_OWNER=NOT_ATTESTED
echo P209_ORIGINAL_P184_RECEIPT=NOT_WIRED
echo P209_ARM64_NODE_HTTP_READY=NOT_WIRED
echo P209_V139=STRUCTURAL_BLOCKED

echo P208_FIXED_SOURCE_REAL_MAINACTIVITY_LIFECYCLE=PASS
echo P208_ORIGINAL_START2_INVOKESUSPEND_ENTRY_OBSERVATION_PROCEDURE=PASS
echo P208_ORIGINAL_PROCESS_OWNER_EPOCH=NOT_ATTESTED
echo P208_ACTUAL_ORIGINAL_PROCESS_READER_LATCH_STATEFLOW=NOT_ATTESTED
echo P208_REAL_OS_OWNER_EPOCH_P184_RECEIPT=NOT_WIRED
echo P208_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P208_V139=STRUCTURAL_BLOCKED
