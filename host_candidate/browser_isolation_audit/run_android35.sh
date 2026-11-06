#!/usr/bin/env bash
# B1 disposable Android35 emulator only. No owner phone or DSH app.
set -euo pipefail
cd "$(dirname "$0")/../../.."
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
count="$(find "$dir/build/outputs/apk/debug" -maxdepth 1 -name '*.apk' -type f | wc -l)"
[[ "$count" -eq 1 ]]
apk="$(find "$dir/build/outputs/apk/debug" -maxdepth 1 -name '*.apk' -type f | head -n1)"
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
adb -s "$serial" shell am start -W -n "$pkg/.MainProbe" >/dev/null
passed=NO
since=
for _ in $(seq 1 45);do
  raw="$(adb -s "$serial" logcat -d -v brief -s B1_BOUNDARY:I B1_PROBE:I '*:S')"
  since="$(printf '%s\n' "$raw" | awk -v marker="$marker" '
    index($0,marker){n++;after=1;next}
    after{print}
    END{if(n!=1)print "B1_INVALID_CURRENT_RUN_BOUNDARY"}
  ')"
  if [[ "$since" == *B1_INVALID_CURRENT_RUN_BOUNDARY* ]];then sleep 1;continue;fi
  if [[ "$since" == *B1_ANDROID35_*"=DENY"* ]];then
    for reason in OWNER_OR_PHASE_MISMATCH RESULT_TIMEOUT A_SET_COOKIE \
      B_SET_COOKIE LOCALSTORAGE_MISMATCH COOKIE_PERSISTENCE_OR_CROSS_PROFILE \
      CROSS_COOKIE_A PREEXISTING_PROFILE_COOKIE B_LOCALSTORAGE_WRITE \
      MAIN_WRONG_PROCESS MISSING_EXACT_PHASE_PROOF ACTIVITY_RECREATED \
      PHASE_OUT_OF_RANGE RESTORE_UNEXPECTED;do
      if [[ "$since" == *"$reason=DENY"* ]];then echo "B1_SAFE_$reason=DENY";fi
    done
    echo B1_ANDROID35_ISOLATION_PROBE=FAIL_CLOSED
    exit 2
  fi
  if [[ "$since" == *B1_ANDROID35_PROCESS_A_B_COOKIE_LOCALSTORAGE_ISOLATION=PASS* &&
        "$since" == *B1_ANDROID35_MAIN_PROCESS_WEBVIEW_DISABLED=PASS* &&
        "$since" == *B1_ANDROID35_SAME_APP_UID_OS_ISOLATION=NOT_ATTESTED* &&
        "$since" == *B1_ANDROID35_AVF_PROTECTED_VM=NOT_ATTESTED* ]];then
    passed=YES;break
  fi
  sleep 1
done
stage=REQUIRED_MARKERS
if [[ "$passed" != YES ]];then echo B1_REQUIRED_ANDROID35_MARKERS_MISSING;exit 2;fi
echo B1_REAL_ANDROID35_TWO_PROCESS_COOKIE_LOCALSTORAGE_ISOLATION=PASS
echo B1_MAIN_PROCESS_WEBVIEW_DISABLED=PASS
echo B1_PROCESS_PROFILE_STORAGE_ONLY_SAME_APP_UID=YES
echo B1_WORK_PROFILE_AND_AVF_PROTECTED_VM=NOT_ATTESTED
echo B1_ORIGINAL_DSH_DATA_AND_APK_TOUCHED=NO
echo B1_ORIGINAL_AI_BROWSER_PROFILE_ROUTING=NOT_WIRED
echo B1_V139_RELEASE=STRUCTURAL_BLOCKED
