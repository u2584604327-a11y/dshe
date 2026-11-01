#!/usr/bin/env bash
set -euo pipefail
test "$GITHUB_ACTIONS" = true
adb() { command adb -s emulator-5554 "$@"; }
test "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1
test "$(adb shell getprop ro.hardware | tr -d '\r')" = ranchu
test "$(adb shell uname -m | tr -d '\r')" = x86_64
case "$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')" in
  *arm64-v8a*) echo P135_GUEST_ARM64_ADVERTISED_BY_SYSTEM=PASS ;;
  *) echo P135_GUEST_ARM64_ADVERTISED_BY_SYSTEM=FAIL; exit 1 ;;
esac
case "$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')" in
  libndk_translation.so|libhoudini.so|libhoudini64.so) echo P135_NATIVE_BRIDGE=CONFIGURED ;;
  *) echo P135_NATIVE_BRIDGE=UNAVAILABLE; exit 1 ;;
esac
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
test -s "$RUNNER_TEMP/p135-disposable.apk"
adb install --no-streaming "$RUNNER_TEMP/p135-disposable.apk" | grep -Fxq Success
trap 'adb shell am force-stop com.dsh.p135 >/dev/null 2>&1 || true; adb uninstall com.dsh.p135 >/dev/null 2>&1 || true' EXIT
adb logcat -c
adb shell am start -W -n com.dsh.p135/.P135HostActivity | grep -Eq 'Status: ok|Status: warning'
for i in $(seq 1 24); do
  logs="$(adb logcat -d -s DSH_P135_REAL_UID:I '*:S' | tr -d '\r')"
  if grep -Fq 'P135_REAL_ANDROID_TRANSLATED_ARM64_DENIED_PREEXEC=PASS' <<< "$logs"; then
    for required in \
      P135_ACTUAL_ANDROID_ISOLATED_UID_DISTINCT=PASS \
      P135_X86_KERNEL_ADVERTISES_ARM64_GUEST=PASS \
      P135_REAL_ANDROID_TRANSLATED_ARM64_DENIED_PREEXEC=PASS \
      P135_ORIGINAL_NODE_EXECUTED=NO \
      P135_ENGINE_MANAGER_EXECUTED=NO \
      P135_P109_NATIVE_AUTHORITY=DENY_ALL \
      P135_V139_RELEASE=BLOCKED; do
      grep -Fq "$required" <<< "$logs" || { echo P135_EMULATOR_PROOF=BLOCKED_INCOMPLETE; exit 1; }
    done
    echo P135_REAL_ANDROID35_X86_NATIVE_BRIDGE_FALSE_POSITIVE=BLOCKED_BY_GATE
    echo P135_ANDROID_ISOLATED_UID_WITNESS=PASS
    echo P135_ORIGINAL_NODE_REAL_ARM64=NOT_TESTED
    echo P135_FORMAL_V139=BLOCKED
    exit 0
  fi
  if grep -Eq 'P135_.*=FAIL' <<< "$logs"; then echo P135_EMULATOR_PROOF=FAIL_REDACTED; exit 1; fi
  sleep 1
done
echo P135_EMULATOR_PROOF=TIMEOUT_NOT_VERIFIED
exit 1
