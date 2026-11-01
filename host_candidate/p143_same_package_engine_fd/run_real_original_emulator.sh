#!/usr/bin/env bash
set -euo pipefail
# Disposable Android emulator ONLY; no user phone/package operation.
test "$(adb shell getprop ro.kernel.qemu | tr -d "\r")" = "1" || { echo P143_BLOCKED_NON_EMULATOR_DEVICE; exit 1; }
adb wait-for-device
adb root
adb wait-for-device
test "$(adb shell getprop ro.kernel.qemu | tr -d "\r")" = "1"
adb shell id | grep -Eq "uid=0\\("
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
test -s "$apk"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
test "$("$sdk/build-tools/35.0.0/aapt" dump badging "$apk" | sed -n "s/^package: name=\x27\([^\x27]*\)\x27.*/\1/p" | head -n1)" = com.dsh.android
adb shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
adb install "$apk" | grep -Fxq Success
uid="$(adb shell pm list packages -U com.dsh.android | sed -n -E "s/^package:com\.dsh\.android uid:([0-9]+).*/\1/p" | tr -d "\r" | head -n1)"
[[ "$uid" =~ ^[0-9]+$ ]]
adb shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb shell iptables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
adb shell ip6tables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
adb logcat -c
launch="$("$sdk/build-tools/35.0.0/aapt" dump badging "$apk" | sed -n "s/^launchable-activity: name=\x27\([^\x27]*\)\x27.*/\1/p" | head -n1)"
test -n "$launch"
adb shell am start -W -n "com.dsh.android/$launch" | grep -Eq "Status: ok|Status: warning"
adb shell pidof com.dsh.android >/dev/null
echo P143_PINNED_ORIGINAL_APP_MAIN_ACTIVITY_LAUNCHED=PASS
adb shell am start -W -n com.dsh.android/com.dsh.android.p43.P43ProbeActivity --ez p76_archive true | grep -Eq "Status: ok|Status: warning"
passed=false
for i in $(seq 1 120); do
  logs="$(adb logcat -d -v brief -s P43_HOST_BINDER:I "*:S")"
  if grep -Fq P143_SAME_PACKAGE_ORIGINAL_ENGINE_FD_ISOLATED_SHA=PASS <<< "$logs" &&
     grep -Fq P77_REAL_ORIGINAL_TAR_FULL_TREE_SHA_MATCH_IN_ISOLATED_UID=PASS <<< "$logs" &&
     grep -Fq P78_BOUNDED_ORIGINAL_JS_BYTES_READ_ONCE_IN_ISOLATED_UID=PASS <<< "$logs" &&
     grep -Fq P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES=PASS <<< "$logs" &&
     grep -Fq P144_ORIGINAL_SCRIPT_AND_PACKAGE_BYTES_ISOLATED=PASS <<< "$logs" &&
     grep -Fq P145_PINNED_ORIGINAL_ENTRY_AND_PACKAGE_ISOLATED=PASS <<< "$logs"; then
    passed=true; break
  fi
  if grep -Eq "P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_|P43_EMBEDDED_ISOLATED_SERVICE_FAIL=|P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_" <<< "$logs"; then
    echo P143_SAME_PACKAGE_ARCHIVE_TRANSFER=BLOCKED
    echo "$logs" | grep -E "P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_|P43_EMBEDDED_ISOLATED_SERVICE_FAIL=|P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_" | tail -n 5
    exit 1
  fi
  sleep 1
done
test "$passed" = true || { echo P143_SAME_PACKAGE_ARCHIVE_FD_ACK_TIMEOUT; exit 1; }
for evidence in P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS P76_REAL_ORIGINAL_ENGINE_GZIP_READONLY_FD_ISOLATED_SHA=PASS P76_ISOLATED_SOURCE_ARCHIVE_NOT_EXECUTED=YES P143_ORIGINAL_APP_ENGINE_SCRIPT_EXECUTED=NO P47_NO_HOST_PROCESSBUILDER_FALLBACK=PASS; do
  grep -Fq "$evidence" <<< "$logs" || { echo P143_REQUIRED_EVIDENCE_MISSING; exit 1; }
done
echo P145_PINNED_CLI_ENTRY_AND_PACKAGE_VERIFIED_IN_ORIGINAL_UID=PASS
echo P145_REAL_MODULE_DEPENDENCIES_AND_READY=NOT_WIRED
echo P144_PRODUCTION_SOURCE_BROKER_TWO_IMMUTABLE_LEASES=PASS
echo P144_NODE_MODULE_RESOLVER_AND_ENGINEMANAGER=NOT_WIRED
echo P143_ORIGINAL_PACKAGE_ISOLATED_FD_FULL_TAR_MODULE=PASS
echo P143_BINDER_FROM_SAME_PACKAGE_APP_TO_ISOLATED_UID=PASS
echo P143_PRODUCTION_JS_EXEC=NOT_AUTHORIZED
echo P143_PROCESS_PROXY_PRODUCTION_HANDOFF=NOT_WIRED
echo P143_FORMAL_V139=BLOCKED
adb shell am force-stop com.dsh.android
adb shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT || true
adb shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT || true
adb shell pm uninstall com.dsh.android >/dev/null
