#!/usr/bin/env bash
# P192: run ONE original-package loopback capability probe on a disposable CI AVD.
# Must not run on physical devices, must not loosen browser or Node permissions.
set -euo pipefail
# Fixed-vocabulary fail-closed diagnostic stages. Do not log private values.
p192_stage="ROOT_IDENTITY"
trap 'rc=$?; printf "P192_DIAG_STAGE_FAILED_%s_EXIT_%s\n" "$p192_stage" "$rc"; exit "$rc"' ERR
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
p192_stage="EMU_IDENTITY"
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
p192_stage="APK_PRESENT_AND_BADGING"
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
[[ -s "$apk" ]]
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
aapt="$sdk/build-tools/35.0.0/aapt"
[[ -x "$aapt" ]]
badging="$("$aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
cleanup() {
  adb -s "$serial" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
  if [[ -n "${uid:-}" ]]; then
    adb -s "$serial" shell iptables -w -D OUTPUT -o lo -d 127.0.0.1/32 -m owner --uid-owner "$uid" -j ACCEPT >/dev/null 2>&1 || true
    adb -s "$serial" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
    adb -s "$serial" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
  fi
  adb -s "$serial" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
}
trap cleanup EXIT
# Distinguish adb command failure from strict success-output mismatch.
# Stage labels and reason codes are fixed vocabulary; no raw adb output.
p192_stage="ADB_INSTALL_COMMAND"
if installed="$(adb -s "$serial" install "$apk" 2>&1)"; then
  :
else
  case "$installed" in
    *INSTALL_FAILED_INSUFFICIENT_STORAGE*) echo P192_ADB_INSTALL_REASON=INSUFFICIENT_STORAGE ;;
    *INSTALL_FAILED_UPDATE_INCOMPATIBLE*) echo P192_ADB_INSTALL_REASON=SIGNER_CONFLICT ;;
    *INSTALL_FAILED_NO_MATCHING_ABIS*) echo P192_ADB_INSTALL_REASON=ABI_MISMATCH ;;
    *INSTALL_PARSE_FAILED*) echo P192_ADB_INSTALL_REASON=APK_PARSE ;;
    *INSTALL_FAILED*) echo P192_ADB_INSTALL_REASON=ANDROID_INSTALL_FAILED_OTHER ;;
    *"device offline"*|*"device not found"*) echo P192_ADB_INSTALL_REASON=ADB_DEVICE_OFFLINE ;;
    *) echo P192_ADB_INSTALL_REASON=ADB_COMMAND_FAILED_OTHER ;;
  esac
  false
fi
p192_stage="ADB_INSTALL_OUTPUT"
installed="$(printf '%s' "$installed" | tr -d '\r')"
# ADB rc must already be zero. Exact last-line Success plus no FAIL/ERROR
# tokens, followed by a separate installed-package/UID and Activity check.
install_last="$(printf '%s' "$installed" | tail -n 1)"
install_upper="$(printf '%s' "$installed" | tr '[:lower:]' '[:upper:]')"
[[ "$install_last" == "Success" && "$install_upper" != *"FAIL"* && "$install_upper" != *"ERROR"* ]]
echo P192_ADB_INSTALL_ACCEPTED_EXACT_FINAL_SUCCESS=PASS
p192_stage="APK_UID_RESOLVE"
packages="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
uid="$(sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' <<< "$packages")"
[[ "$uid" =~ ^[0-9]+$ ]]
# Reject all egress for the host UID, except its own IPv4 loopback path.
# Never grant permissions to isolated UID or allow remote network access.
p192_stage="NETWORK_IPTABLES_REJECT_IPV4"
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
p192_stage="NETWORK_IPTABLES_REJECT_IPV6"
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
p192_stage="NETWORK_IPTABLES_LOOPBACK_ONLY"
adb -s "$serial" shell iptables -w -I OUTPUT 1 -o lo -d 127.0.0.1/32 -m owner --uid-owner "$uid" -j ACCEPT
# Consume the entire rules output before checking: grep -q under pipefail
# can SIGPIPE an upstream aapt/adb command after matching the first line.
p192_stage="NETWORK_RULES_AUDIT"
rules="$(adb -s "$serial" shell iptables -S OUTPUT)"
[[ "$rules" == *"--uid-owner $uid"*"-j REJECT"* ]]
[[ "$rules" == *"--uid-owner $uid"*"-j ACCEPT"* ]]
launch="$(sed -n "s/^launchable-activity: name=\x27\([^\x27]*\)\x27.*/\1/p" <<< "$badging")"
[[ -n "$launch" ]]
p192_stage="APP_MAIN_ACTIVITY_START"
activity_start="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$activity_start" =~ Status:\ (ok|warning) ]]
p192_stage="APP_PID_CHECK"
adb -s "$serial" shell pidof com.dsh.android >/dev/null
# Strict harness writes a new run boundary; old PASS logs are not admissible.
p192_stage="P187B_ACTUAL_LOOPBACK_GATE"
bash host_candidate/p192_loopback_android35/run_android35_emulator_only.sh "$serial"
echo P192_ANDROID35_P187_EMULATOR_LOOPBACK_GATE=PASS
echo P192_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_TESTED
