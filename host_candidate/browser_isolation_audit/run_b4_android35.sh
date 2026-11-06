#!/usr/bin/env bash
# B4: fresh, disposable Android35 QEMU ONLY; never run on personal hardware.
set -euo pipefail
cd "$(dirname "$0")/../.."
serial=emulator-5554
pkg=com.dsh.b4probe
work=""
installed=NO
stage=EMULATOR
cleanup(){
  if [[ "$installed" == YES ]];then adb -s "$serial" uninstall "$pkg" >/dev/null 2>&1 || true; fi
  if [[ -n "$work" ]];then adb -s "$serial" shell pm remove-user "$work" >/dev/null 2>&1 || true; fi
}
on_exit(){ rc=$?; cleanup; if [[ "$rc" -ne 0 ]];then echo "B4_STAGE_$stage=DENY";fi; }
trap on_exit EXIT
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r\n')" == 35 ]]
[[ "$(adb -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r\n')" == x86_64 ]]
[[ "$(adb -s "$serial" shell getprop sys.boot_completed | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell pm list packages "$pkg" | tr -d '\r')" != *"package:$pkg"* ]]
list="$(adb -s "$serial" shell pm list users | tr -d '\r')"
[[ "$list" == *"UserInfo{0:"* && "$list" != *"profile.MANAGED"* ]]
stage=PROFILE
made="$(adb -s "$serial" shell pm create-user --profileOf 0 --user-type android.os.usertype.profile.MANAGED --for-testing B4Disposable | tr -d '\r')"
work="$(printf '%s\n' "$made" | sed -nE 's/^Success: created user id ([0-9]+)$/\1/p')"
[[ "$work" =~ ^[0-9]+$ ]] && (( work>0 && work<100 ))
adb -s "$serial" shell am start-user "$work" >/dev/null
[[ "$(adb -s "$serial" shell pm list users | tr -d '\r')" == *"UserInfo{$work:"* ]]
stage=INSTALL
apk=host_candidate/browser_isolation_audit/b4_os_user_probe/.b4-disposable.apk
[[ -s "$apk" && -n "$ANDROID_HOME" ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.b4probe'"* && "$badging" != *"uses-permission:"* ]]
adb -s "$serial" install --user 0 "$apk" >/dev/null
installed=YES
adb -s "$serial" install --user "$work" "$apk" >/dev/null
get_uid(){
  adb -s "$serial" shell pm list packages --user "$1" -U "$pkg" |
    tr -d '\r' | sed -nE 's/^package:com\.dsh\.b4probe uid:([0-9]+)$/\1/p'
}
uid0="$(get_uid 0)"
uidw="$(get_uid "$work")"
[[ "$uid0" =~ ^[0-9]+$ && "$uidw" =~ ^[0-9]+$ ]]
(( uid0>10000 && uidw>10000 && uid0!=uidw ))
(( uid0/100000==0 && uidw/100000==work ))
(( uid0%100000==uidw%100000 ))
echo B4_ANDROID35_DIFFERENT_OS_USER_UIDS=PASS
boundary="B4_BOUNDARY_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$boundary" =~ ^B4_BOUNDARY_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t B4_BOUNDARY "$boundary" >/dev/null
after_boundary(){
  adb -s "$serial" logcat -d -v brief -s B4_BOUNDARY:I B4_PROBE:I '*:S' |
    awk -v marker="$boundary" '
      index($0,marker){n++;live=1;next}
      live{print}
      END{if(n!=1)print "B4_INVALID_MARKER"}
    '
}
wait_for(){
  target="$1"
  for _ in $(seq 1 45);do
    trace="$(after_boundary)"
    if [[ "$trace" == *"B4_INVALID_MARKER"* || "$trace" == *"=DENY"* ]];then
      echo B4_PROBE_FAILED
      exit 2
    fi
    if [[ "$trace" == *"$target"* ]];then return 0;fi
    sleep 1
  done
  echo B4_REQUIRED_MARKER_MISSING
  exit 2
}
probe(){
  local user="$1" role="$2" phase="$3" other="$4"
  adb -s "$serial" shell am force-stop --user "$user" "$pkg" >/dev/null
  adb -s "$serial" shell am start -W --user "$user" -n "$pkg/.UserProbe" \
    --es phase "$phase" --ei other "$other" >/dev/null
  if [[ "$phase" == seed ]];then
    wait_for "B4_ANDROID35_$role""_SEED=PASS"
  else
    wait_for "B4_ANDROID35_$role""_VERIFY=PASS"
  fi
}
stage=STORAGE
probe 0 PARENT seed "$work"
probe "$work" WORK seed 0
probe 0 PARENT verify "$work"
probe "$work" WORK verify 0
echo B4_ANDROID35_OS_MANAGED_USER_PRIVATE_STORAGE=PASS
echo B4_ENTERPRISE_DPC_AND_CROSS_PROFILE_POLICY=NOT_ATTESTED
echo B4_ORIGINAL_DSH_AND_PHONE_TOUCHED=NO
echo B4_AVF_PROTECTED_VM=NOT_ATTESTED
echo B4_V139_RELEASE=STRUCTURAL_BLOCKED
