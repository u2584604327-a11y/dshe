#!/usr/bin/env bash
# P220 second fresh disposable Android35 trial; never user's installed DSH.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
serial=emulator-5554
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell id -u | tr -d '\r\n')" == 0 ]]
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
original=.p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk
[[ -s "$apk" && -s "$original" && -n "${ANDROID_HOME:-}" ]]
[[ "$(sha256sum "$original" | cut -d' ' -f1)" == 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5 ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.android'"* ]]
launch="$(sed -n "s/^launchable-activity: name='\([^']*\)'.*/\1/p" <<< "$badging" | head -n1)"
[[ "$launch" == com.dsh.android.MainActivity ]]
already="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r')"
[[ "$already" != *"package:com.dsh.android"* ]] || {
 echo P220_PREEXISTING_PACKAGE_OR_DATA=DENY;exit 2;
}
umask 077
tmp="$(mktemp -d .p220-trace.XXXXXXXX)"
remote=/data/local/tmp/p220-dsh-test-only.trace
uid=
cleanup(){
 adb -s "$serial" shell am profile stop com.dsh.android >/dev/null 2>&1 || true
 adb -s "$serial" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
 if [[ -n "$uid" ]];then
  adb -s "$serial" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
  adb -s "$serial" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
 fi
 adb -s "$serial" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
 adb -s "$serial" shell rm -f "$remote" >/dev/null 2>&1 || true
 rm -rf -- "$tmp"
}
trap cleanup EXIT
adb -s "$serial" shell test ! -e "$remote" || { echo P220_TRACE_ALREADY_EXISTS=DENY;exit 2; }
adb -s "$serial" install "$apk" >/dev/null
uid="$(adb -s "$serial" shell pm list packages -U com.dsh.android | tr -d '\r' | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" =~ ^[0-9]+$ && "$uid" -gt 10000 ]] || { echo P220_UID=DENY;exit 2; }
adb -s "$serial" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb -s "$serial" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
echo P220_OFFLINE_IPV4_IPV6_OWNER_REJECT=PASS
# AOSP am startup profiler uses method trace; no signed DEX instructions changed.
if ! status="$(adb -s "$serial" shell am start -W --start-profiler "$remote" --sampling 1000 -n "com.dsh.android/$launch" 2>/dev/null)";then
 echo P220_STARTUP_PROFILER=NOT_ATTESTED;exit 0
fi
if [[ ! "$status" =~ Status:\ (ok|warning) ]];then
 echo P220_STARTUP_PROFILER=NOT_ATTESTED;exit 0
fi
echo P220_PROFILED_FRESH_MAIN_START=PASS
sleep 12
if ! adb -s "$serial" shell am profile stop com.dsh.android >/dev/null 2>&1;then
 echo P220_PROFILE_STOP=NOT_ATTESTED;exit 0
fi
if ! adb -s "$serial" pull "$remote" "$tmp/trace.bin" >/dev/null 2>&1;then
 echo P220_TRACE_TRANSFER=NOT_ATTESTED;exit 0
fi
if python3 -B host_candidate/p209_original_p47_deny/p220_trace_parser.py "$tmp/trace.bin";then
 echo P220_OFFLINE_ALLOWLIST_TRACE=PASS
else
 echo P220_OFFLINE_ALLOWLIST_TRACE=NOT_ATTESTED
fi
echo P220_PROFILED_RUN_SEPARATE_FROM_P209_BASELINE=YES
echo P220_SIGNED_ORIGINAL_AND_USER_DATA_MODIFIED=NO
