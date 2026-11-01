#!/usr/bin/env bash
# P127: an OFFLINE, disposable Google APIs emulator test of exact original Node.
# Only adb shell's UID is tested, never Android isolated Service or user phone.
set -euo pipefail
staged="$1"
test -s "$staged/bin/node"
test -d "$staged/lib"
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1"
adb shell cmd connectivity airplane-mode enable
adb shell svc wifi disable || true
adb shell svc data disable || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = "1"
arch="$(adb shell uname -m | tr -d '\r')"
abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
bridge="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
exec_flag="$(adb shell getprop ro.enable.native.bridge.exec | tr -d '\r')"
echo "P127_GOOGLE_APIS_KERNEL_ARCH=$arch"
if test "$arch" != x86_64; then
  echo 'P127_UNEXPECTED_SYSTEM_IMAGE_CPU=BLOCKED'
  exit 1
fi
case "$abis" in
  *arm64-v8a*) has_arm64=YES ;;
  *) has_arm64=NO ;;
esac
echo "P127_GOOGLE_APIS_ARM64_ABI_ADVERTISED=$has_arm64"
case "$bridge" in
  ""|"0"|"none") native=NO ;;
  "libndk_translation.so"|"libhoudini.so"|"libhoudini64.so") native=YES ;;
  *) native=UNVERIFIED ;;
esac
echo "P127_GOOGLE_APIS_NATIVE_BRIDGE_CONFIGURED=$native"
case "$exec_flag" in
  "1"|"true") echo 'P127_NATIVE_BRIDGE_EXEC_PROP=ON_UNVERIFIED' ;;
  *) echo 'P127_NATIVE_BRIDGE_EXEC_PROP=OTHER_OR_DISABLED' ;;
esac
binfmt="$(adb shell 'if test -r /proc/sys/fs/binfmt_misc/arm64_exe; then echo ARM64_EXE_REGISTERED; else echo ARM64_EXE_NOT_OBSERVED; fi' | tr -d '\r')"
echo "P127_BINFMT_ARM64_EXEC=$binfmt"
echo 'P127_ORIGINAL_ARM64_NODE_ISOLATED_UID=NOT_TESTED'
echo 'P127_P109_TOOL_ACCESS=DENY_ALL'
if test "$native" != YES || test "$has_arm64" != YES; then
  echo 'P127_ORIGINAL_ARM64_NODE_VERSION=NOT_ATTEMPTED_NATIVE_BRIDGE_UNAVAILABLE'
  exit 0
fi

# Fixed path ONLY in disposable emulator; no user APK/phone, credentials or model.
remote=/data/local/tmp/dsh-p127-original-node-probe
cleanup() { adb shell "rm -rf $remote" >/dev/null 2>&1 || true; }
trap cleanup EXIT
adb shell "mkdir -p $remote/bin $remote/lib"
adb push "$staged/bin/node" "$remote/bin/node" >/dev/null
adb push "$staged/lib/." "$remote/lib/" >/dev/null
adb shell "chmod 700 $remote/bin/node"
digest="$(adb shell "sha256sum $remote/bin/node" | tr -d '\r' | awk '{print $1}')"
if test "$digest" != a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6; then
  echo '::error::P127 original Node SHA drifted during ADB staging'
  exit 1
fi
echo 'P127_ORIGINAL_ARM64_ELF_DEVICE_SHA256=PASS'
# Hard timeout on the ADB invocation. Output is inspected locally and NEVER
# printed verbatim; no Node scripts, network, shell command from the model.
set +e
response="$(timeout 20s adb shell "LD_LIBRARY_PATH=$remote/lib $remote/bin/node --version" 2>&1)"
code=$?
set -e
clean="$(printf '%s' "$response" | tr -d '\r\n')"
if test "$code" -eq 0 && printf '%s\n' "$clean" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "P127_ORIGINAL_ARM64_NODE_VERSION_IN_EMULATOR_SHELL=PASS"
  echo "P127_ORIGINAL_ARM64_NODE_VERSION=$clean"
  echo 'P127_ORIGINAL_ARM64_NODE_IN_ISOLATED_APP=NOT_TESTED'
else
  if test "$code" -eq 124; then
    failure=TIMEOUT
  elif printf '%s\n' "$response" | grep -Eqi 'linker|cannot locate|CANNOT LINK|not found'; then
    failure=DYNAMIC_LOADER_OR_LIBRARY
  elif printf '%s\n' "$response" | grep -Eqi 'exec format|architecture'; then
    failure=ELF_ARCH_OR_BRIDGE
  elif printf '%s\n' "$response" | grep -Eqi 'Permission denied|denied'; then
    failure=EXECUTE_PERMISSION
  else
    failure=OTHER_FAIL_CLOSED
  fi
  echo "P127_ORIGINAL_ARM64_NODE_VERSION_IN_EMULATOR_SHELL=BLOCKED_$failure"
  echo 'P127_NODE_FAILED_RESULT_NOT_RETRIED'
fi
echo 'P127_ORIGINAL_ARM64_NODE_IN_ISOLATED_APP=NOT_TESTED'
