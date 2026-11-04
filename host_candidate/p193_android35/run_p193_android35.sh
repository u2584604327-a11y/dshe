#!/usr/bin/env bash
# P193 disposable Android35 emulator and source-pinned original APK ONLY.
set -euo pipefail
cd "$(dirname "$0")/../.."
stage=ROOT
trap 'rc=$?; if [[ $rc -ne 0 ]]; then echo "P193_STAGE_FAILED_$stage"; fi' EXIT
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
stage=APK
[[ -s "$apk" && -n "$ANDROID_HOME" ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
stage=PREINSTALL
before="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$before" != *"package:com.dsh.android"* ]] || { echo P193_EXISTING_APP_DENY; exit 2; }
uid=
cleanup(){
  adb -s "$serial" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
  if [[ -n "$uid" ]]; then
    adb -s "$serial" shell iptables -w -D OUTPUT -o lo -d 127.0.0.1/32 -m owner --uid-owner "$uid" -j ACCEPT >/dev/null 2>&1 || true
    adb -s "$serial" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
    adb -s "$serial" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
  fi
  adb -s "$serial" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
}
trap cleanup EXIT
stage=INSTALL
if installed="$(adb -s "$serial" install "$apk" 2>&1)"; then :;else
  echo P193_INSTALL_DENIED;exit 2
fi
[[ "$installed" != *INSTALL_FAILED* && "$installed" != *Failure* && "$installed" != *Error:* ]]
stage=HOST_UID
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android |
  tr -d '\r' | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]]
paths="$(adb -s "$serial" shell pm path com.dsh.android | tr -d '\r')"
[[ "$paths" == *package:*base.apk* ]]
echo P193_FRESH_ORIGINAL_DERIVED_PACKAGE_UID=PASS
stage=NETWORK_DENY_PUBLIC
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell iptables -w -I OUTPUT 1 -o lo -d 127.0.0.1/32 -m owner --uid-owner "$uid" -j ACCEPT
rules="$(adb -s "$serial" shell iptables -S OUTPUT)"
[[ "$rules" == *"--uid-owner $uid"*" -j ACCEPT"* &&
   "$rules" == *"--uid-owner $uid"*" -j REJECT"* ]]
echo P193_HOST_NETWORK_ONLY_127001=PASS
stage=REAL_APP_LAUNCH
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ -n "$launch" ]]
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]]
adb -s "$serial" shell pidof com.dsh.android >/dev/null
stage=REAL_BINDER
marker="P193_RUN_START_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P193_RUN_START_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P193_BOUNDARY "$marker" >/dev/null
status="$(adb -s "$serial" shell am start -W -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p193_host_ipc true)"
[[ "$status" =~ Status:\ (ok|warning) ]]
ok=NO
for _ in $(seq 1 25); do
  log="$(adb -s "$serial" logcat -d -v brief \
    -s P193_BOUNDARY:I P43_HOST_BINDER:I P193_WORKER:I '*:S')"
  since="$(printf '%s\n' "$log" | awk -v marker="$marker" '
    index($0,marker){count++;started=1;next}
    started{print}
    END{if(count!=1)print "P193_MARKER_ERROR"}
  ')"
  if [[ "$since" == *P193_MARKER_ERROR* ]];then sleep 1;continue;fi
  if [[ "$since" == *"P193_ANDROID35_"*"=DENY"* ]];then
    echo P193_ANDROID35_SAFETY_REJECTION;exit 2
  fi
  if [[ "$since" == *P193_ANDROID35_HOST_LOOPBACK_BINDER_TWO_UID=PASS* &&
        "$since" == *P193_ANDROID35_FRAMEWORK_SENDING_UID_AUTH=PASS* &&
        "$since" == *P193_ANDROID35_BINDER_DUPLICATE_FRAME_REJECT=PASS* &&
        "$since" == *P193_ANDROID35_WRONG_SESSION_DROPPED=PASS* &&
        "$since" == *P193_ANDROID35_WORKER_NO_NETWORK_BINDER_ACK=PASS* &&
        "$since" == *P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS* ]];then
    ok=YES;break
  fi
  sleep 1
done
[[ "$ok" == YES ]] || { echo P193_ANDROID35_REAL_UID_BINDER_PROOF_MISSING;exit 2; }
echo P193_ANDROID35_HOST_LOOPBACK_AND_REAL_UID_BINDER=PASS
echo P193_ANDROID35_WRONG_SESSION_AND_REPLAY=PASS
echo P193_ANDROID35_ISOLATED_TCP=NOT_USED
echo P193_ANDROID35_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P193_V139=STRUCTURAL_BLOCKED
