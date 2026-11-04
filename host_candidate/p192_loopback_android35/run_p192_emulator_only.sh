#!/usr/bin/env bash
# P192: run ONE original-package loopback capability probe on a disposable CI AVD.
# Must not run on physical devices, must not loosen browser or Node permissions.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
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
installed="$(adb -s "$serial" install "$apk")"
[[ "$installed" == "Success" ]]
packages="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
uid="$(sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' <<< "$packages")"
[[ "$uid" =~ ^[0-9]+$ ]]
# Reject all egress for the host UID, except its own IPv4 loopback path.
# Never grant permissions to isolated UID or allow remote network access.
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell iptables -w -I OUTPUT 1 -o lo -d 127.0.0.1/32 -m owner --uid-owner "$uid" -j ACCEPT
# Consume the entire rules output before checking: grep -q under pipefail
# can SIGPIPE an upstream aapt/adb command after matching the first line.
rules="$(adb -s "$serial" shell iptables -S OUTPUT)"
[[ "$rules" == *"--uid-owner $uid"*"-j REJECT"* ]]
[[ "$rules" == *"--uid-owner $uid"*"-j ACCEPT"* ]]
launch="$(sed -n "s/^launchable-activity: name=\x27\([^\x27]*\)\x27.*/\1/p" <<< "$badging")"
[[ -n "$launch" ]]
activity_start="$(adb -s "$serial" shell am start -W -n "com.dsh.android/$launch")"
[[ "$activity_start" =~ Status:\ (ok|warning) ]]
adb -s "$serial" shell pidof com.dsh.android >/dev/null
# Strict harness writes a new run boundary; old PASS logs are not admissible.
bash host_candidate/p192_loopback_android35/run_android35_emulator_only.sh "$serial"
echo P192_ANDROID35_P187_EMULATOR_LOOPBACK_GATE=PASS
echo P192_ORIGINAL_NODE_HTTP_TOKEN_READY=NOT_TESTED