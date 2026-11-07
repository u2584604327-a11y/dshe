#!/usr/bin/env bash
# P129: bounded, read-only Native Bridge guest linker topology on disposable emulator.
set -euo pipefail
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
test "$(adb shell uname -m | tr -d '\r')" = x86_64
bridge="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
case "$bridge" in
  libndk_translation.so|libhoudini.so|libhoudini64.so) echo P129_BRIDGE_PROPERTY=KNOWN_TRANSLATOR ;;
  *) echo P129_BRIDGE_PROPERTY=UNKNOWN_OR_DISABLED; exit 0 ;;
esac
case "$abis" in *arm64-v8a*) echo P129_GUEST_ABI=ADVERTISED ;; *) echo P129_GUEST_ABI=NOT_ADVERTISED; exit 0 ;; esac
# Fixed allowlist only; no find / no wildcard / no output of private paths.
check_file() {
  local key="$1" path="$2"
  local result
  result="$(adb shell "if test -f '$path'; then echo PRESENT; elif test -e '$path'; then echo NOT_REGULAR_FILE; else echo ABSENT; fi" | tr -d '\r')"
  case "$result" in PRESENT|NOT_REGULAR_FILE|ABSENT) ;; *) result=UNCLASSIFIED ;; esac
  echo "P129_${key}=${result}"
}
check_file TRANSLATOR_SYSTEM_LIB64 /system/lib64/libndk_translation.so
check_file TRANSLATOR_SYSTEM_EXT_LIB64 /system_ext/lib64/libndk_translation.so
check_file TRANSLATOR_VENDOR_LIB64 /vendor/lib64/libndk_translation.so
check_file GUEST_SYSTEM_LINKER64 /system/bin/arm64/linker64
check_file GUEST_SYSTEM_LINKER64_ALT /system/bin/arm64-v8a/linker64
check_file GUEST_SYSTEM_LIBC /system/lib64/arm64/libc.so
check_file GUEST_SYSTEM_LIBC_ALT /system/lib64/arm64-v8a/libc.so
check_file LINKER_CONFIG_SYSTEM /system/etc/ld.config.txt
check_file LINKER_CONFIG_APEX /linkerconfig/ld.config.txt
check_file LINKER_CONFIG_APEX_OTHER /linkerconfig/ld.config.64.txt
# Native bridge resolver's effective mappings are not determined by existence checks.
echo P129_EFFECTIVE_GUEST_LIBRARY_RESOLUTION=NOT_PROVEN
echo P129_GUEST_LINKER_NAMESPACE=NOT_PROVEN
echo P129_ORIGINAL_NODE_EXECUTION=NOT_ATTEMPTED
echo P129_ANDROID_ISOLATED_UID=NOT_TESTED
echo P129_P109_NATIVE_TOOL_AUTHORITY=DENY_ALL
