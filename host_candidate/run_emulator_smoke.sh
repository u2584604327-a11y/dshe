#!/usr/bin/env bash
# DSH private offline emulator smoke. ONLY run on a fresh disposable emulator.
# Do NOT use the original fixed signer or any real diagnostics, app data or accounts.
set -euo pipefail
lab_apk="${1:?Provide disposable debug-signed APK}"
instrument_apk="${2:-}"
sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1"
test -s "$lab_apk"

# P126: observe real emulator ABI/native bridge BEFORE installing any APK.
# These Android properties are not proof of execve/bionic linker support for
# the original SHA-pinned AArch64 Node ELF. No ARM binary is executed here.
p126_arch="$(adb shell uname -m | tr -d '\r')"
p126_abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
p126_bridge="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
p126_exec="$(adb shell getprop ro.enable.native.bridge.exec | tr -d '\r')"
p126_binfmt="$(adb shell 'if test -d /proc/sys/fs/binfmt_misc; then echo PRESENT; else echo ABSENT; fi' | tr -d '\r')"
case "$p126_arch" in
  x86_64|i686|aarch64) ;;
  *) echo '::error::P126 emulator CPU architecture unexpected'; exit 1 ;;
esac
if test -z "$p126_abis" || test "${#p126_abis}" -gt 180; then
  echo '::error::P126 Android CPU ABI list missing or unbounded'; exit 1
fi
case "$p126_bridge" in
  ""|"0"|"none"|"libndk_translation.so"|"libhoudini.so"|"libhoudini64.so") ;;
  *) echo 'P126_NATIVE_BRIDGE_PROPERTY=OTHER_UNCLASSIFIED' ;;
esac
echo "P126_ANDROID_EMULATOR_MACHINE=$p126_arch"
case "$p126_abis" in
  *arm64-v8a*) echo 'P126_SUPPORTED_ABI_HAS_ARM64=YES' ;;
  *) echo 'P126_SUPPORTED_ABI_HAS_ARM64=NO' ;;
esac
case "$p126_bridge" in
  ""|"0"|"none") echo 'P126_NATIVE_BRIDGE_PROPERTY=ABSENT_OR_DISABLED' ;;
  "libndk_translation.so"|"libhoudini.so"|"libhoudini64.so")
    echo 'P126_NATIVE_BRIDGE_PROPERTY=CONFIGURED_ONLY'
    ;;
esac
case "$p126_exec" in
  ""|"0"|"false") echo 'P126_NATIVE_BRIDGE_EXEC_FLAG=NOT_ENABLED_OR_UNSET' ;;
  "1"|"true") echo 'P126_NATIVE_BRIDGE_EXEC_FLAG=ENABLED_UNVERIFIED' ;;
  *) echo 'P126_NATIVE_BRIDGE_EXEC_FLAG=UNCLASSIFIED' ;;
esac
echo "P126_BINFMT_DIRECTORY=$p126_binfmt"
echo 'P126_ORIGINAL_ARM64_NODE_ELF_EXECVE=NOT_TESTED'
echo 'P126_ORIGINAL_ARM64_NODE_ISOLATED_UID=NOT_TESTED'
echo 'P126_P109_NATIVE_TOOLS=DENY_ALL'

# All app execution is restricted to a clean emulator after an airplane mode gate.
# This does not claim full OS-level network namespace isolation.
adb shell cmd connectivity airplane-mode enable
adb shell svc wifi disable || true
adb shell svc data disable || true
airplane="$(adb shell settings get global airplane_mode_on | tr -d '\r')"
test "$airplane" = "1" || { echo "::error::Emulator airplane mode not confirmed"; exit 1; }

if adb shell pm list packages com.dsh.android | grep -q '^package:com.dsh.android$'; then
  echo "::error::Not a clean emulator: DSH already installed."
  exit 1
fi
adb install --no-streaming "$lab_apk"
adb shell pm path com.dsh.android | grep -q 'package:'
aapt="$sdk_root/build-tools/35.0.0/aapt"
badging="$("$aapt" dump badging "$lab_apk")"
pkgline="$(printf '%s\n' "$badging" | grep '^package: ' | head -n1)"
[[ "$pkgline" == *"name='com.dsh.android'"* ]]
[[ "$pkgline" == *"versionCode='138'"* ]]

# ART dex2oat compile on a disposable, offline emulator. This is not proof
# of every P5 addon class being loaded or of real-phone behavior.
set +e
compile_result="$(adb shell cmd package compile -m speed -f com.dsh.android 2>&1)"
compile_code=$?
set -e
printf '%s\n' "$compile_result" | head -c 1000
if test "$compile_code" -ne 0 || printf '%s\n' "$compile_result" | grep -Eqi 'Failure|Exception|Error:'; then
  echo "::error::Offline ART package compiler rejected the lab candidate"
  exit 1
fi
echo "ANDROID_ART_OFFLINE_PACKAGE_COMPILE=PASS"

# Prefer manifest's launchable component; original DSH may use explicit
# MainActivity without a standard MAIN/LAUNCHER resolution.
launch_activity="$(printf '%s\n' "$badging" | sed -n -E "s/^launchable-activity: name='([^']+)'.*/\\1/p" | head -n1)"
if test -z "$launch_activity"; then
  launch_activity="com.dsh.android.MainActivity"
  echo "NO_LAUNCHABLE_MANIFEST_ENTRY=YES_TRY_EXPLICIT_MAIN"
fi
adb logcat -c
set +e
start_result="$(adb shell am start -W -n "com.dsh.android/$launch_activity" 2>&1)"
start_code=$?
set -e
printf '%s\n' "$start_result" | head -c 1500
if test "$start_code" -ne 0 || printf '%s\n' "$start_result" | grep -Eqi 'Error:|Exception|not found|unable to resolve|SecurityException'; then
  echo "::error::Explicit Android Activity launch blocked"
  exit 1
fi
sleep 8
adb logcat -d -t 6000 > /tmp/dsh-private-emulator-logcat.txt
if grep -E 'FATAL EXCEPTION|VerifyError|NoClassDefFoundError|IncompatibleClassChangeError|IllegalAccessError|ClassNotFoundException' /tmp/dsh-private-emulator-logcat.txt | grep -E 'com\.dsh\.android|com\.dsh\.p1|Process: com\.dsh\.android' >/dev/null; then
  echo "::error::DSH-related ART or startup exception detected in disposable emulator."
  grep -E 'FATAL EXCEPTION|VerifyError|NoClassDefFoundError|IncompatibleClassChangeError|IllegalAccessError|Process: com\.dsh\.android' /tmp/dsh-private-emulator-logcat.txt | head -n 24 || true
  exit 1
fi
if ! adb shell pidof com.dsh.android >/dev/null; then
  echo "::error::DSH process did not remain alive after launch."
  exit 1
fi
echo "DISPOSABLE_ANDROID_EMULATOR_LAUNCH=PASS"
echo "DEX_VERIFICATION_AT_STARTUP=PARTIAL_NO_CRASH_OBSERVED"
echo "P5_ADDON_CLASSES_LOADED=NOT_VERIFIED"
echo "NATIVE_DIAGNOSTIC_EGRESS=NOT_VERIFIED"
echo "REAL_PHONE_AND_DATA_PRESERVATION=NOT_VERIFIED"
# Separate, same-ephemeral-signer instrumentation from a disposable APK.
# Do not infer original UI wiring from a test directly invoking the P5 class.
if test -n "$instrument_apk"; then
  test -s "$instrument_apk"
  adb install --no-streaming "$instrument_apk"
  adb shell pm path com.dsh.p1.smoketest | grep -q '^package:'
  # Prove startup registration on a truly fresh DSH process, before any
  # P5/P12 test has had a chance to install listeners. No app user data read.
  adb shell am force-stop com.dsh.android
  # P13 does NOT call P12.attach() from instrumentation; the only allowed
  # installer is original DSH's AndroidX Startup provider registered through
  # the exact modified binary AXML in the test app package.
  set +e
  p13_output="$(adb shell am instrument -w -r \
    com.dsh.p1.smoketest/.P13AutoHookInstrumentation 2>&1)"
  p13_status=$?
  set -e
  printf '%s\\n' "$p13_output" | head -c 4000
  if test "$p13_status" -ne 0 || \
    ! printf '%s\\n' "$p13_output" | grep -q 'P13_LOGVIEWER_AUTOMATIC_HOOK=PASS_NO_MANUAL_ATTACH' || \
    ! printf '%s\\n' "$p13_output" | grep -q 'P13_ANDROIDX_STARTUP_METADATA=PASS_REAL_APPLICATION' || \
    ! printf '%s\\n' "$p13_output" | grep -q 'INSTRUMENTATION_CODE: -1'; then
    echo "::error::P13 AndroidX Startup original LogViewer automatic hook FAILED"
    exit 1
  fi
  echo 'P13_ORIGINAL_LOGVIEWER_AUTOHOOK=PASS_ANDROID35_NO_MANUAL_ATTACH'
  echo 'P13_APPROVED_DIAGNOSTIC_TRANSPORT=NOT_CONNECTED'
  set +e
  test_output="$(adb shell am instrument -w -r \
    com.dsh.p1.smoketest/.DshInstrumentation 2>&1)"
  test_status=$?
  set -e
  printf '%s\\n' "$test_output" | head -c 4000
  # P163: do not conflate present instrumentation PASS markers with
  # adb transport exit status or printf|grep -q SIGPIPE. Keep the same
  # seven mandatory gates, never accept nonzero adb or missing evidence.
  source "$(dirname "$0")/p163_p5_instrumentation_evidence.sh"
  if ! p163_check_p5_instrumentation "$test_status" "$test_output"; then
    echo "::error::P5 NativeDiagnosticReview real Activity UI smoke FAILED"
    exit 1
  fi
  echo 'P5_NATIVE_UI_VISIBLE_ON_ANDROID=PASS_INSTRUMENTATION'
  echo 'P5_UI_NOT_WIRED_TO_LEGACY_BUTTON=STILL_TRUE'
  # P12 hooks original LogViewerActivity buttons using test instrumentation;
  # the production Activity lifecycle STILL does not call P12.attach().
  set +e
  p12_output="$(adb shell am instrument -w -r \
    com.dsh.p1.smoketest/.P12LogViewerInstrumentation 2>&1)"
  p12_status=$?
  set -e
  printf '%s\\n' "$p12_output" | head -c 4000
  if test "$p12_status" -ne 0 || \
    ! printf '%s\\n' "$p12_output" | grep -q 'P12_EXISTING_EXPORT_UPLOAD_BUTTONS=BOTH_INTERCEPTED_TEST_CALL' || \
    ! printf '%s\\n' "$p12_output" | grep -q 'INSTRUMENTATION_CODE: -1'; then
    echo "::error::P12 original LogViewerActivity user-button interception FAILED"
    exit 1
  fi
  echo 'P12_ORIGINAL_LOGVIEWER_USER_BUTTONS=PASS_TEST_ONLY_ATTACH'
  echo 'P12_TEST_INSTRUMENTATION_USER_BUTTONS=PASS'

fi

