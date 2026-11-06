#!/usr/bin/env bash
# Disposable Android35 emulator ONLY. Never install on owner's phone or original DSH.
set -euo pipefail
cd "$(dirname "$0")/../.."
stage=INIT
host_pkg=com.dsh.b3probe
attacker_pkg=com.dsh.b3attacker
serial=emulator-5554
host_installed=NO
attacker_installed=NO
cleanup(){
  if [[ "$attacker_installed" == YES ]];then
    adb -s "$serial" shell am force-stop "$attacker_pkg" >/dev/null 2>&1 || true
    adb -s "$serial" uninstall "$attacker_pkg" >/dev/null 2>&1 || true
  fi
  if [[ "$host_installed" == YES ]];then
    adb -s "$serial" shell am force-stop "$host_pkg" >/dev/null 2>&1 || true
    adb -s "$serial" uninstall "$host_pkg" >/dev/null 2>&1 || true
  fi
}
on_exit(){
  rc=$?
  cleanup
  if [[ $rc -ne 0 ]];then echo "B3_STAGE_$stage=DENY";fi
}
trap on_exit EXIT
stage=EMULATOR
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r\n')" == 35 ]]
[[ "$(adb -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r\n')" == x86_64 ]]
for pkg in "$host_pkg" "$attacker_pkg";do
  if [[ "$(adb -s "$serial" shell pm list packages "$pkg" | tr -d '\r')" == *"package:$pkg"* ]];then
    echo B3_PREEXISTING_TEST_PACKAGE=DENY
    exit 2
  fi
done
stage=PACKAGE_VERIFY
p=host_candidate/browser_isolation_audit
host_apk="$p/b3_android_probe/.b3-host-disposable.apk"
attacker_apk="$p/b3_attacker/.b3-attacker-disposable.apk"
[[ -s "$host_apk" && -s "$attacker_apk" ]]
[[ -n "$ANDROID_HOME" ]]
host_badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$host_apk")"
attacker_badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$attacker_apk")"
[[ "$host_badging" == *"package: name='com.dsh.b3probe'"* ]]
[[ "$attacker_badging" == *"package: name='com.dsh.b3attacker'"* ]]
[[ "$host_badging" != *"uses-permission:"* ]]
[[ "$attacker_badging" != *"uses-permission:"* ]]
stage=INSTALL
adb -s "$serial" install "$host_apk" >/dev/null
host_installed=YES
adb -s "$serial" install "$attacker_apk" >/dev/null
attacker_installed=YES
marker="B3_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^B3_BOUNDARY_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t B3_BOUNDARY "$marker" >/dev/null
after_marker(){
  adb -s "$serial" logcat -d -v brief -s B3_BOUNDARY:I B3_PROBE:I '*:S' |
    awk -v marker="$marker" '
      index($0,marker){seen++;valid=1;next}
      valid{print}
      END{if(seen!=1)print "B3_CURRENT_RUN_BOUNDARY_INVALID"}
    '
}
wait_for(){
  local expected="$1" output
  for _ in $(seq 1 50);do
    output="$(after_marker)"
    if [[ "$output" == *"B3_CURRENT_RUN_BOUNDARY_INVALID"* ||
          "$output" == *"=DENY"* ]];then
      echo B3_PROOF_INVALID_OR_REJECTED
      return 2
    fi
    if [[ "$output" == *"$expected"* ]];then return 0;fi
    sleep 1
  done
  echo B3_PROOF_NOT_OBSERVED
  return 2
}
stage=HOST_TRANSACTION
adb -s "$serial" shell am start -W -n "$host_pkg/.HostProbe" >/dev/null
wait_for B3_ANDROID35_TRANSACTION_UID_AND_DISTINCT_PROCESSES=PASS
wait_for B3_ANDROID35_WRONG_SLOT_REPLAY_EPOCH_REVOKE=PASS
wait_for B3_ANDROID35_BOUNDED_RESULT_ONE_SHOT=PASS
wait_for B3_ANDROID35_HOST_CLOCK_AND_REAL_PAYLOAD_SIZE=PASS
wait_for B3_ANDROID35_SHARED_UID_HOSTILE_PROCESS_ISOLATION=NOT_ATTESTED
wait_for B3_ORIGINAL_DSH_AND_USER_DATA_TOUCHED=NO
stage=EXTERNAL_CROSS_UID
adb -s "$serial" shell am start -W -n "$attacker_pkg/.AttackerProbe" >/dev/null
wait_for B3_ANDROID35_EXTERNAL_DIFFERENT_UID_DENIED_IN_TRANSACTION=PASS
wait_for B3_V139_RELEASE=STRUCTURAL_BLOCKED
echo B3_ANDROID35_REAL_BINDER_UID_NEGATIVE_PROOF=PASS
echo B3_ANDROID35_CROSS_SLOT_REPLAY_RESULT_REVOKE=PASS
echo B3_REAL_ANDROID35_SAME_UID_NOT_SECURITY_BOUNDARY=YES
echo B3_ANDROID_WORK_PROFILE_AVF=NOT_ATTESTED
echo B3_ORIGINAL_DSH_APK_AND_DATA_TOUCHED=NO
echo B3_V139_RELEASE=STRUCTURAL_BLOCKED
