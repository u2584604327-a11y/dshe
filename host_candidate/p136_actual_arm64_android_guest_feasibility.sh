#!/usr/bin/env bash
# P136: CI-only genuine ARM64 Android system-image boot feasibility.
# Never use Node, DSH, app credentials, Android tool APIs or user phone.
set -euo pipefail
report() { printf '%s\n' "$1"; printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"; }
test "$GITHUB_ACTIONS" = true || { echo P136_CI_ONLY=REFUSED; exit 1; }
test "$(uname -m)" = x86_64 || { report P136_HOST_ARCH=UNSUPPORTED; exit 0; }
sdk="$ANDROID_HOME"
test -d "$sdk" || { report P136_SDK=UNAVAILABLE; exit 0; }
manager="$(command -v sdkmanager || true)"
test -n "$manager" || manager="$(find "$sdk/cmdline-tools" -type f -name sdkmanager -perm /111 2>/dev/null | head -n1 || true)"
test -n "$manager" || { report P136_SDKMANAGER=UNAVAILABLE; exit 0; }
emulator="$sdk/emulator/emulator"
if ! test -x "$emulator"; then
  report P136_HOST_EMULATOR_PREINSTALLED=NO
  set +e
  timeout 180s "$manager" --sdk_root="$sdk" --install emulator > "$RUNNER_TEMP/p136-emulator-install.log" 2>&1
  rc=$?
  set -e
  if test "$rc" != 0 || ! test -x "$emulator"; then
    report P136_HOST_EMULATOR_INSTALL=UNAVAILABLE_OR_TIMED_OUT
    report P136_ARM64_ANDROID_BOOT=NOT_TESTED
    exit 0
  fi
fi
report P136_HOST_EMULATOR_BINARY=AVAILABLE
root="$RUNNER_TEMP/p136-arm64-only"
test ! -e "$root" || { report P136_TEMP_PATH_ALREADY_EXISTS=STOP; exit 1; }
mkdir -p "$root/avd"
export ANDROID_AVD_HOME="$root/avd"
export ANDROID_I_WANT_MY_TCG=yes
pkg='system-images;android-35;google_apis;arm64-v8a'
avd_name=p136_actual_arm64_android35
pid=''
cleanup() {
  if test -n "$pid"; then kill "$pid" >/dev/null 2>&1 || true; wait "$pid" >/dev/null 2>&1 || true; fi
  rm -rf -- "$root"
}
trap cleanup EXIT
report P136_HOST=x86_64
report P136_REQUIRED_ANDROID_GUEST_KERNEL=aarch64
report P136_EMULATION=UNSUPPORTED_SOFTWARE_TCG_BOUNDED
set +e
timeout 90s "$manager" --sdk_root="$sdk" --list > "$root/list.txt" 2>&1
listed=$?
set -e
if test "$listed" != 0; then
  report P136_ANDROID_SDK_INVENTORY=UNAVAILABLE
  report P136_ARM64_ANDROID_BOOT=NOT_TESTED
  exit 0
fi
if ! grep -Fq "$pkg" "$root/list.txt"; then
  report P136_API35_ARM64_SYSTEM_IMAGE=NOT_LISTED
  report P136_ARM64_ANDROID_BOOT=NOT_TESTED
  exit 0
fi
report P136_API35_ARM64_SYSTEM_IMAGE=LISTED
set +e
timeout 210s "$manager" --sdk_root="$sdk" --install "$pkg" > "$root/install.txt" 2>&1
installed=$?
set -e
if test "$installed" != 0; then
  report P136_ARM64_IMAGE_INSTALL=UNAVAILABLE_OR_TIMED_OUT
  report P136_ARM64_ANDROID_BOOT=NOT_TESTED
  exit 0
fi
image_dir="$sdk/system-images/android-35/google_apis/arm64-v8a"
# SDK package layouts differ; do not assert a single system.img filename.
if ! test -d "$image_dir"; then
  report P136_ARM64_IMAGE_DIRECTORY=ABSENT_AFTER_INSTALL_RETURNED_ZERO
  report P136_ANDROID_ARM64_BOOT=NOT_TESTED
  exit 0
fi
if ! test -f "$image_dir/source.properties"; then
  report P136_ARM64_IMAGE_PACKAGE_METADATA=ABSENT
  report P136_ANDROID_ARM64_BOOT=NOT_TESTED
  exit 0
fi
count="$(find "$image_dir" -maxdepth 1 -type f -name '*.img' | wc -l | tr -d ' ')"
if test "$count" = 0; then
  report P136_ARM64_IMAGE_FILES=NONE_VISIBLE
  report P136_ANDROID_ARM64_BOOT=NOT_TESTED
  exit 0
fi
report P136_ARM64_IMAGE_PACKAGE_METADATA=PASS
report P136_ARM64_IMAGE_FILE_COUNT="$count"
report P136_ARM64_SYSTEM_IMAGE_INSTALLED=PASS_METADATA_AND_FILES
avdm="$(command -v avdmanager || true)"
test -n "$avdm" || avdm="$(find "$sdk/cmdline-tools" -type f -name avdmanager -perm /111 2>/dev/null | head -n1 || true)"
if test -z "$avdm"; then report P136_AVDMANAGER=UNAVAILABLE; exit 0; fi
set +e
printf 'no\n' | timeout 40s "$avdm" create avd -n "$avd_name" -k "$pkg" --force > "$root/avd.txt" 2>&1
made=$?
set -e
if test "$made" != 0; then
  report P136_ARM64_AVD_CREATION=UNAVAILABLE
  report P136_ARM64_ANDROID_BOOT=NOT_TESTED
  exit 0
fi
report P136_ARM64_AVD=CREATED_DISPOSABLE
timeout --signal=TERM --kill-after=7s 240s "$emulator" -avd "$avd_name" \
  -accel off -no-window -no-snapshot -noaudio -no-boot-anim \
  -gpu swiftshader_indirect -no-metrics -dns-server 192.0.2.1 \
  > "$root/emu.log" 2>&1 &
pid=$!
booted=NO
for i in $(seq 1 36); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then break; fi
  set +e
  b="$(timeout 6s "$sdk/platform-tools/adb" -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
  rc=$?
  set -e
  if test "$rc" = 0 && test "$b" = 1; then booted=YES; break; fi
  sleep 6
done
if test "$booted" != YES; then
  report P136_REAL_ARM64_ANDROID_BOOT=NOT_PROVEN_WITHIN_240S_TCG
  report P136_ANDROID_ISOLATED_UID=NOT_TESTED
  exit 0
fi
emulated="$(timeout 7s "$sdk/platform-tools/adb" -s emulator-5554 shell getprop ro.kernel.qemu | tr -d '\r')"
kernel="$(timeout 7s "$sdk/platform-tools/adb" -s emulator-5554 shell uname -m | tr -d '\r')"
abi="$(timeout 7s "$sdk/platform-tools/adb" -s emulator-5554 shell getprop ro.product.cpu.abi | tr -d '\r')"
if test "$emulated" = 1 && test "$kernel" = aarch64 && test "$abi" = arm64-v8a; then
  report P136_REAL_ARM64_ANDROID_BOOT=PASS_REAL_GUEST_KERNEL_AARCH64
  report P136_ANDROID_PRIMARY_ABI=PASS_ARM64_V8A
  timeout 8s "$sdk/platform-tools/adb" -s emulator-5554 shell cmd connectivity airplane-mode enable >/dev/null 2>&1 || true
else
  report P136_REAL_ARM64_ANDROID_BOOT=NOT_PROVEN_KERNEL_ABI_MISMATCH
fi
report P136_ANDROID_ISOLATED_UID=NOT_TESTED
report P136_ORIGINAL_NODE_EXECUTED=NO
report P136_ENGINE_MANAGER_EXECUTED=NO
report P136_P109_NATIVE_TOOLS=DENY_ALL
report P136_FORMAL_V139=BLOCKED
