#!/usr/bin/env bash
# B1 disposable Android35 emulator only. No owner phone or DSH app.
set -euo pipefail
# This script lives two directories beneath repo root, not three.
cd "$(dirname "$0")/../.."
stage=INIT
trap 'rc=$?; if [[ $rc -ne 0 ]];then echo "B1_STAGE_FAILED_$stage";fi' EXIT
serial=emulator-5554
pkg=com.dsh.b1probe
stage=EMULATOR
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r\n')" == 35 ]]
[[ "$(adb -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r\n')" == x86_64 ]]
before="$(adb -s "$serial" shell pm list packages "$pkg" | tr -d '\r')"
[[ "$before" != *"package:$pkg"* ]] || { echo B1_PREEXISTING_PROBE_DENY;exit 2; }
stage=APK
dir=host_candidate/browser_isolation_audit/android_probe
apk="$dir/.b1-verified-disposable.apk"
[[ -s "$apk" ]]
[[ -n "$ANDROID_HOME" ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.b1probe'"* ]]
installed=NO
cleanup() {
  if [[ "$installed" == YES ]];then
    adb -s "$serial" shell am force-stop "$pkg" >/dev/null 2>&1 || true
    adb -s "$serial" shell pm uninstall "$pkg" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
stage=INSTALL
adb -s "$serial" install "$apk" >/dev/null
installed=YES
echo B1_EPHEMERAL_TEST_APP_ONLY=PASS
stage=REAL_PROCESS_TEST
marker="B1_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^B1_BOUNDARY_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t B1_BOUNDARY "$marker" >/dev/null

# Check only fixed result categories created after the unique marker in the
# current boot. Never emit cookie values, PIDs, raw page JS or unbounded logcat.
after_boundary() {
  local raw
  raw="$(adb -s "$serial" logcat -d -v brief -s B1_BOUNDARY:I B1_PROBE:I '*:S')"
  printf '%s\n' "$raw" | awk -v marker="$marker" '
    index($0,marker){n++;after=1;next}
    after{print}
    END{if(n!=1)print "B1_INVALID_CURRENT_RUN_BOUNDARY"}
  '
}
wait_for_proof() {
  local expected="$1"
  local trace reason
  for _ in $(seq 1 45);do
    trace="$(after_boundary)"
    if [[ "$trace" == *B1_INVALID_CURRENT_RUN_BOUNDARY* ]];then
      sleep 1
      continue
    fi
    if [[ "$trace" == *B1_ANDROID35_*"=DENY"* ]];then
      for reason in OWNER_OR_PHASE_MISMATCH RESULT_TIMEOUT A_SET_COOKIE \
        B_SET_COOKIE LOCALSTORAGE_MISMATCH COOKIE_PERSISTENCE_OR_CROSS_PROFILE \
        CROSS_COOKIE_A PREEXISTING_PROFILE_COOKIE B_LOCALSTORAGE_WRITE \
        MAIN_WRONG_PROCESS MISSING_EXACT_PHASE_PROOF ACTIVITY_RECREATED \
        PHASE_OUT_OF_RANGE RESTORE_UNEXPECTED MODE_REQUIRED \
        INDEXEDDB_INVALID_OPERATION INDEXEDDB_START INDEXEDDB_TIMEOUT \
        INDEXEDDB_VALUE_OR_ERROR \
        B2_MAIN_PROCESS B2_CONTROLLER_PROCESS B2_SERVICE_IDENTITY \
        B2_BINDER_DISCONNECTED B2_TIMEOUT B2_BIND B2_MISSING_BINDER \
        B2_IPC_SEND B2_OS_PID_UID B2_SAME_PROCESS \
        B2_SLOT_CHECK B2_IPC_ORDER_REPLAY;do
        if [[ "$trace" == *"$reason=DENY"* ]];then echo "B1_SAFE_$reason=DENY";fi
      done
      echo B1_ANDROID35_ISOLATION_PROBE=FAIL_CLOSED
      return 2
    fi
    if [[ "$trace" == *"$expected"* &&
          "$trace" == *B1_ANDROID35_MAIN_PROCESS_WEBVIEW_DISABLED=PASS* &&
          "$trace" == *B1_ANDROID35_SAME_APP_UID_OS_ISOLATION=NOT_ATTESTED* &&
          "$trace" == *B1_ANDROID35_AVF_PROTECTED_VM=NOT_ATTESTED* ]];then
      return 0
    fi
    sleep 1
  done
  echo B1_ANDROID35_REQUIRED_PROOF_MISSING
  return 2
}
# A fresh Android35 emulator can recreate MainProbe during first-start
# configuration settling. That old Activity's phase must NEVER be restored.
# Only this exact failure category permits ONE full disposable-package wipe
# and re-execution of ALL original A-B-A-B seed checks from empty storage.
# Any data, slot, identity, IndexedDB, cookie or other failure stays fatal.
stage=SEED_BOUNDED_FRESH_RETRY
seed_success=NO
for attempt in 1 2;do
  adb -s "$serial" shell am start -W -n "$pkg/.MainProbe" --es mode seed >/dev/null
  if wait_for_proof B1_ANDROID35_PROCESS_A_B_COOKIE_LOCALSTORAGE_ISOLATION=PASS &&
     wait_for_proof B1_ANDROID35_PROCESS_A_B_INDEXEDDB_ISOLATION=PASS;then
    seed_success=YES
    break
  fi
  [[ "$attempt" -eq 1 ]] || {
    echo B1_SEED_SECOND_ATTEMPT_FAILED_CLOSED=DENY
    exit 2
  }
  trace="$(after_boundary)"
  [[ "$trace" == *B1_ANDROID35_ACTIVITY_RECREATED=DENY* ]] || {
    echo B1_SEED_RETRY_REASON_NOT_ACTIVITY_RECREATION=DENY
    exit 2
  }
  other_denials="$(printf '%s\n' "$trace" |
    grep -Eo 'B1_ANDROID35_[A-Z0-9_]+=DENY' |
    grep -v '^B1_ANDROID35_ACTIVITY_RECREATED=DENY$' || true)"
  [[ -z "$other_denials" ]] || {
    echo B1_SEED_RETRY_OTHER_DENIAL_PRESENT=DENY
    exit 2
  }
  [[ "$pkg" == com.dsh.b1probe ]] || exit 2
  adb -s "$serial" shell am force-stop "$pkg" >/dev/null
  running="$(adb -s "$serial" shell 'pidof com.dsh.b1probe com.dsh.b1probe:slotA com.dsh.b1probe:slotB || true' | tr -d '\r\n')"
  [[ -z "$running" ]] || { echo B1_SEED_RETRY_PROCESS_STILL_ALIVE=DENY;exit 2; }
  cleared="$(adb -s "$serial" shell pm clear "$pkg" | tr -d '\r\n')"
  [[ "$cleared" == Success ]] || { echo B1_SEED_RETRY_CLEAR_FAILED=DENY;exit 2; }
  echo B1_ONLY_DISPOSABLE_ACTIVITY_RECREATION_FULL_RESEED=1
  # New current-run boundary; never reuse a prior A/B success marker.
  marker="B1_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
  [[ "$marker" =~ ^B1_BOUNDARY_[a-f0-9]{24}$ ]] || exit 2
  adb -s "$serial" shell log -p i -t B1_BOUNDARY "$marker" >/dev/null
done
[[ "$seed_success" == YES ]] || { echo B1_SEED_NOT_ATTESTED=DENY;exit 2; }
echo B1_REAL_ANDROID35_TWO_PROCESS_COOKIE_LOCALSTORAGE_ISOLATION=PASS
echo B1_REAL_ANDROID35_TWO_PROCESS_INDEXEDDB_ISOLATION=PASS

# Real OS force-stop, not WebView.reload(), CookieManager.flush() alone or
# Activity recreation. Fail if any of the app's 3 named processes survives.
stage=OS_FORCE_STOP
adb -s "$serial" shell am force-stop "$pkg" >/dev/null
running="$(adb -s "$serial" shell 'pidof com.dsh.b1probe com.dsh.b1probe:slotA com.dsh.b1probe:slotB || true' | tr -d '\r\n')"
if [[ -n "$running" ]];then
  echo B1_ANDROID35_FORCE_STOP_PROCESS_STILL_RUNNING=DENY
  exit 2
fi
echo B1_ANDROID35_ALL_THREE_PROCESS_NAMES_STOPPED=PASS
stage=AFTER_RESTART_TEST
adb -s "$serial" shell am start -W -n "$pkg/.MainProbe" --es mode restart >/dev/null
wait_for_proof B1_ANDROID35_RESTART_A_B_COOKIE_LOCALSTORAGE_ISOLATION=PASS
wait_for_proof B1_ANDROID35_RESTART_A_B_INDEXEDDB_ISOLATION=PASS
echo B1_REAL_ANDROID35_AFTER_FORCE_STOP_PERSISTENT_COOKIE_LOCALSTORAGE=PASS
echo B1_REAL_ANDROID35_AFTER_FORCE_STOP_PERSISTENT_INDEXEDDB=PASS
# B2 is a separate proof: two concurrently bound live slot processes,
# each performing a simultaneous mutation and later cross-slot negative
# recheck of real Cookie/LocalStorage/IndexedDB. Do not fake with prior B1.
stage=B2_CONCURRENT_LIVE_PROCESSES
adb -s "$serial" shell am force-stop "$pkg" >/dev/null
running="$(adb -s "$serial" shell 'pidof com.dsh.b1probe com.dsh.b1probe:slotA com.dsh.b1probe:slotB || true' | tr -d '\r\n')"
if [[ -n "$running" ]]; then
  echo B1_ANDROID35_B2_PROCESS_REMAINING=DENY
  exit 2
fi
adb -s "$serial" shell am start -W -n "$pkg/.MainProbe" --es mode concurrent >/dev/null
wait_for_proof B2_ANDROID35_DISTINCT_LIVE_PIDS_SAME_APP_UID=PASS
wait_for_proof B2_ANDROID35_LIVE_A_B_COOKIE_LOCALSTORAGE_INDEXEDDB=PASS
wait_for_proof B2_ANDROID35_OS_USER_OR_VM=NOT_ATTESTED
echo B2_REAL_ANDROID35_TWO_LIVE_PROCESSES_MUTATION_ISOLATION=PASS
echo B2_REAL_ANDROID35_DISTINCT_PIDS_SAME_UID=PASS
echo B2_ANDROID35_WORK_PROFILE_AVF=NOT_ATTESTED
echo B1_MAIN_PROCESS_WEBVIEW_DISABLED=PASS
echo B1_PROCESS_PROFILE_STORAGE_ONLY_SAME_APP_UID=YES
echo B1_WORK_PROFILE_AND_AVF_PROTECTED_VM=NOT_ATTESTED
echo B1_ORIGINAL_DSH_DATA_AND_APK_TOUCHED=NO
echo B1_ORIGINAL_AI_BROWSER_PROFILE_ROUTING=NOT_WIRED
echo B1_V139_RELEASE=STRUCTURAL_BLOCKED
