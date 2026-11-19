#!/usr/bin/env bash
# P308: one same-session disposable original-derived APK, P143 original FD + P193 host-only loopback; NEVER release.
set -euo pipefail
cd "$(dirname "$0")/../.."
stage=ROOT
trap 'rc=$?; if [[ $rc -ne 0 ]]; then echo "P308_STAGE_FAILED_$stage"; fi' EXIT
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
marker="P308_RUN_START_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P308_RUN_START_[a-f0-9]{24}$ ]]
adb -s "$serial" shell log -p i -t P308_BOUNDARY "$marker" >/dev/null
status="$(adb -s "$serial" shell am start -W -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p193_host_ipc true --ez p76_archive true)"
[[ "$status" =~ Status:\ (ok|warning) ]]
ok=NO
for _ in $(seq 1 120); do
  log="$(adb -s "$serial" logcat -d -v brief \
    -s P308_BOUNDARY:I P43_HOST_BINDER:I P193_WORKER:I '*:S')"
  since="$(printf '%s\n' "$log" | awk -v marker="$marker" '
    index($0,marker){count++;started=1;next}
    started{print}
    END{if(count!=1)print "P308_MARKER_ERROR"}
  ')"
  if [[ "$since" == *P308_MARKER_ERROR* ]];then sleep 1;continue;fi
  if [[ "$since" == *"P193_ANDROID35_"*"=DENY"* || 
        "$since" == *"P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_"* ||
        "$since" == *"P43_EMBEDDED_ISOLATED_SERVICE_FAIL="* ||
        "$since" == *"P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_"* ]];then
    # All diagnostic output is an explicit, finite allowlist of fixed status
    # codes. Never print raw logcat, UID/session/nonce/token or arbitrary
    # exception text, even on failing tests.
    for code in \
      P193_ANDROID35_FRAMEWORK_SENDER_UID \
      P193_ANDROID35_FRAME_SCHEMA \
      P193_ANDROID35_REPLAY_OR_FRAME \
      P193_ANDROID35_MALFORMED_FRAME \
      P193_ANDROID35_LOOPBACK_SERVER_ERROR \
      P193_ANDROID35_LOOPBACK_SERVER_TIMEOUT \
      P193_ANDROID35_LOOPBACK_OR_BINDER_VALIDATION \
      P193_ANDROID35_HTTP_STATUS_MISMATCH \
      P193_ANDROID35_HTTP_BODY_MISMATCH \
      P193_ANDROID35_BINDER_ACCEPT_MISSING \
      P193_ANDROID35_REPLAY_NOT_OBSERVED \
      P193_ANDROID35_REPLAY_NOT_DENIED \
      P193_ANDROID35_FIXED_FIXTURE_ERROR \
      P193_ANDROID35_REVOKED_BINDER; do
      if [[ "$since" == *"$code=DENY"* ]];then
        echo "P193_SAFE_DIAGNOSTIC_${code}=DENY"
      fi
    done
    for extra in P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_ P43_EMBEDDED_ISOLATED_SERVICE_FAIL= P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_;do
      if [[ "$since" == *"$extra"* ]];then
        echo P308_ORIGINAL_ARCHIVE_OR_LIFECYCLE=DENY
      fi
    done
    echo P308_ANDROID35_SAFETY_REJECTION;exit 2
  fi
  if [[ "$since" == *P193_ANDROID35_HOST_LOOPBACK_BINDER_TWO_UID=PASS* &&
        "$since" == *P193_ANDROID35_FRAMEWORK_SENDING_UID_AUTH=PASS* &&
        "$since" == *P193_ANDROID35_BINDER_DUPLICATE_FRAME_REJECT=PASS* &&
        "$since" == *P193_ANDROID35_WRONG_SESSION_DROPPED=PASS* &&
        "$since" == *P193_ANDROID35_WORKER_NO_NETWORK_BINDER_ACK=PASS* &&
        "$since" == *P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS* &&
        "$since" == *P143_SAME_PACKAGE_ORIGINAL_ENGINE_FD_ISOLATED_SHA=PASS* &&
        "$since" == *P77_REAL_ORIGINAL_TAR_FULL_TREE_SHA_MATCH_IN_ISOLATED_UID=PASS* &&
        "$since" == *P78_BOUNDED_ORIGINAL_JS_BYTES_READ_ONCE_IN_ISOLATED_UID=PASS* &&
        "$since" == *P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES=PASS* &&
        "$since" == *P145_PINNED_ORIGINAL_ENTRY_AND_PACKAGE_ISOLATED=PASS* &&
        "$since" == *P146_ORIGINAL_CLI_DIRECT_IMPORT_HINT_SCAN=PASS* &&
        "$since" == *P147_ONE_SCOPED_RELATIVE_CANDIDATE_FD_SECOND_ROOT=PASS* ]];then
    ok=YES;break
  fi
  sleep 1
done
if [[ "$ok" != YES ]];then
  # A missing proof is not silently normalized to a success.
  # Print only known marker names, no values and no full logcat.
  for code in \
    P193_ANDROID35_HOST_LOOPBACK_BINDER_TWO_UID \
    P193_ANDROID35_FRAMEWORK_SENDING_UID_AUTH \
    P193_ANDROID35_BINDER_DUPLICATE_FRAME_REJECT \
    P193_ANDROID35_WRONG_SESSION_DROPPED \
    P193_ANDROID35_WORKER_NO_NETWORK_BINDER_ACK \
    P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID \
    P143_SAME_PACKAGE_ORIGINAL_ENGINE_FD_ISOLATED_SHA \
    P77_REAL_ORIGINAL_TAR_FULL_TREE_SHA_MATCH_IN_ISOLATED_UID \
    P78_BOUNDED_ORIGINAL_JS_BYTES_READ_ONCE_IN_ISOLATED_UID \
    P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES \
    P145_PINNED_ORIGINAL_ENTRY_AND_PACKAGE_ISOLATED \
    P146_ORIGINAL_CLI_DIRECT_IMPORT_HINT_SCAN \
    P147_ONE_SCOPED_RELATIVE_CANDIDATE_FD_SECOND_ROOT; do
    if [[ "$since" != *"$code=PASS"* ]];then
      echo "P193_MISSING_REQUIRED_PROOF_${code}"
    fi
  done
  echo P308_SAME_SESSION_REQUIRED_PROOF_MISSING;exit 2
fi
# One single P43 Activity start, one original-derived package and verified
# session, both same worker. Missing/duplicate fixed markers DENY, and no
# original Node execution or production readiness is authorized.
for required in \
  P193_ANDROID35_HOST_LOOPBACK_BINDER_TWO_UID \
  P193_ANDROID35_FRAMEWORK_SENDING_UID_AUTH \
  P193_ANDROID35_BINDER_DUPLICATE_FRAME_REJECT \
  P193_ANDROID35_WRONG_SESSION_DROPPED \
  P193_ANDROID35_WORKER_NO_NETWORK_BINDER_ACK \
  P143_SAME_PACKAGE_ORIGINAL_ENGINE_FD_ISOLATED_SHA \
  P77_REAL_ORIGINAL_TAR_FULL_TREE_SHA_MATCH_IN_ISOLATED_UID \
  P78_BOUNDED_ORIGINAL_JS_BYTES_READ_ONCE_IN_ISOLATED_UID \
  P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES \
  P145_PINNED_ORIGINAL_ENTRY_AND_PACKAGE_ISOLATED \
  P146_ORIGINAL_CLI_DIRECT_IMPORT_HINT_SCAN \
  P147_ONE_SCOPED_RELATIVE_CANDIDATE_FD_SECOND_ROOT; do
  count="$(printf '%s\n' "$since" | grep -Fc "$required=PASS" || true)"
  if [[ "$count" != 1 ]];then echo P308_DUPLICATE_OR_MISSING_PROOF=DENY;exit 2;fi
done
echo P308_ONE_ORIGINAL_DERIVED_APK_AND_SESSION=PASS
echo P308_REAL_ANDROID35_BOTH_ORIGINAL_ARCHIVE_FD_AND_HOST_LOOPBACK=PASS
echo P308_FRAMEWORK_BINDER_UID_SESSION_REPLAY=PASS
echo P308_REAL_ORIGINAL_ENGINE_TAR_AND_BOUNDED_JS_SOURCE=PASS
echo P308_ISOLATED_UID_TCP_LISTEN=NOT_USED
echo P308_ORIGINAL_NODE_MODULE_EXECUTION=NOT_WIRED
echo P308_ORIGINAL_ENGINEMANAGER_HTTP_TOKEN_READY=NOT_WIRED
echo P308_P245_P192_B3_B4_RELEASE_GATES=UNMODIFIED_DENY
echo P308_V139_RELEASE=STRUCTURAL_BLOCKED
