#!/usr/bin/env bash
# P197 actual Android35 emulator and original-v138-derived ephemeral APK only.
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
before="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$before" != *"package:com.dsh.android"* ]] || {
  echo P197_PREEXISTING_PACKAGE_DENY;exit 2;
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
if installed="$(adb -s "$serial" install "$apk" 2>&1)";then :;else
  echo P197_TEST_APK_INSTALL_FAILED;exit 2;
fi
[[ "$installed" != *INSTALL_FAILED* && "$installed" != *Failure* &&
   "$installed" != *Error:* ]]
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' |
  sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]]
paths="$(adb -s "$serial" shell pm path com.dsh.android | tr -d '\r')"
[[ "$paths" == *package:*base.apk* ]]
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P197_ANDROID35_FRESH_DERIVED_APP_AND_NO_HOST_EGRESS=PASS
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ -n "$launch" ]]
status="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$status" =~ Status:\ (ok|warning) ]]
adb -s "$serial" shell pidof com.dsh.android >/dev/null
marker="P197_START_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P197_START_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P197_BOUNDARY "$marker" >/dev/null
status="$(adb -s "$serial" shell am start -W -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p184_receipt true)"
[[ "$status" =~ Status:\ (ok|warning) ]]
verified=NO
for _ in $(seq 1 28); do
  log="$(adb -s "$serial" logcat -d -v brief \
    -s P197_BOUNDARY:I P43_HOST_BINDER:I '*:S')"
  selected="$(printf '%s\n' "$log" | awk -v marker="$marker" '
    index($0,marker){count++;after=1;next}
    after{print}
    END{if(count!=1)print "P197_INVALID_RUN_BOUNDARY"}
  ')"
  if [[ "$selected" == *P197_INVALID_RUN_BOUNDARY* ]];then sleep 1;continue;fi
  if [[ "$selected" == *"P197_ANDROID35_"*"=DENY"* ||
        "$selected" == *"P197_ANDROID35_"*"=FAIL"* ]];then
    for category in \
      P197_ANDROID35_SINGLETON_NOT_INITIALIZED \
      P197_ANDROID35_SINGLETON_REFLECTION \
      P197_ANDROID35_HOST_OWNER_PRECONDITION \
      P197_ANDROID35_P75_PROCESS_MISMATCH \
      P197_ANDROID35_P75_CROSS_THREAD_FAILED \
      P197_ANDROID35_P75_DID_NOT_WAIT \
      P197_ANDROID35_P75_INTERRUPTED \
      P197_ANDROID35_P48_CHILD_TRANSPORT; do
      if [[ "$selected" == *"$category=DENY"* ]];then
        echo "P197_SAFE_CLASSIFICATION_${category}=DENY"
      fi
    done
    echo P197_ANDROID35_SAFETY_REJECTED;exit 2
  fi
  if [[ "$selected" == *P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS* &&
        "$selected" == *P197_ANDROID35_EXISTING_ORIGINAL_SINGLETON_AND_HOST_UID_PID=PASS* &&
        "$selected" == *P197_ANDROID35_OWNER_EPOCH_REVOKED_AFTER_HANDOFF=PASS* &&
        "$selected" == *P197_ANDROID35_P75_FIXED_ENGINE_THREAD_WAITING=PASS* &&
        "$selected" == *P197_ANDROID35_P75_LEGACY_BYPASS_DENIED=PASS* &&
        "$selected" == *P197_ANDROID35_P68_TO_P75_ONCE=PASS* &&
        "$selected" == *P197_ANDROID35_REPLAY_DENIED=PASS* &&
        "$selected" == *P197_ANDROID35_P68_FRAMEWORK_RECEIPT=PASS* &&
        "$selected" == *P197_ANDROID35_P75_CROSS_THREAD_EXACT_PROCESS=PASS* &&
        "$selected" == *P197_ANDROID35_FIXED_ISOLATED_CHILD_EXIT=PASS* &&
        "$selected" == *P197_ANDROID35_REAL_P40_ORIGINAL_COROUTINE=NOT_INVOKED* ]];then
    verified=YES;break
  fi
  sleep 1
done
if [[ "$verified" != YES ]];then
  for required in \
    P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID \
    P197_ANDROID35_EXISTING_ORIGINAL_SINGLETON_AND_HOST_UID_PID \
    P197_ANDROID35_P75_FIXED_ENGINE_THREAD_WAITING \
    P197_ANDROID35_P75_LEGACY_BYPASS_DENIED \
    P197_ANDROID35_P68_TO_P75_ONCE \
    P197_ANDROID35_REPLAY_DENIED \
    P197_ANDROID35_P68_FRAMEWORK_RECEIPT \
    P197_ANDROID35_P75_CROSS_THREAD_EXACT_PROCESS \
    P197_ANDROID35_FIXED_ISOLATED_CHILD_EXIT \
    P197_ANDROID35_OWNER_EPOCH_REVOKED_AFTER_HANDOFF; do
    if [[ "$selected" != *"$required=PASS"* ]];then
      echo "P197_MISSING_REQUIRED_MARKER_${required}"
    fi
  done
  echo P197_ANDROID35_ACTUAL_RECEIPT_PROOF_INCOMPLETE;exit 2
fi
echo P197_ANDROID35_ACTUAL_ORIGINAL_HOST_SINGLETON_UID_PID_EPOCH=PASS
echo P197_ANDROID35_REAL_MESSAGE_SENDING_UID_TO_ONE_USE_RECEIPT=PASS
echo P197_ANDROID35_P68_P75_EXACT_PROCESS_AND_REPLAY_DENY=PASS
echo P197_ANDROID35_FIXED_ISOLATED_ID_UID_ONLY=PASS
echo P197_ANDROID35_ORIGINAL_P40_ENGINE_COROUTINE=NOT_INVOKED
echo P197_ANDROID35_REAL_KOTLIN_COROUTINE_GENERATION=NOT_ATTESTED
echo P197_ANDROID35_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_WIRED
echo P197_FORMAL_V139=STRUCTURAL_BLOCKED
