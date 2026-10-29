#!/usr/bin/env bash
# DSH private offline emulator smoke. ONLY run on a fresh disposable emulator.
# Do NOT use the original fixed signer or any real diagnostics, app data or accounts.
set -euo pipefail
lab_apk="${1:?Provide disposable debug-signed APK}"
sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1"
test -s "$lab_apk"

# All app execution is restricted to a clean emulator after an airplane mode gate.
# This does not claim full OS-level network namespace isolation.
adb shell cmd connectivity airplane-mode enable
adb shell svc wifi disable || true
adb shell svc data disable || true
airplane="$(adb shell settings get global airplane_mode_on | tr -d '\r')"
test "$airplane" = "1" || { echo "::error::Emulator airplane mode not confirmed"; exit 1; }

if adb shell pm list packages com.dsh.android | grep -q '^package:com.dsh.android
adb install --no-streaming "$lab_apk"
adb shell pm path com.dsh.android | grep -q 'package:'
aapt="$sdk_root/build-tools/35.0.0/aapt"
badging="$("$aapt" dump badging "$lab_apk")"
pkgline="$(printf '%s\n' "$badging" | grep '^package: ' | head -n1)"
[[ "$pkgline" == *"name='com.dsh.android'"* ]]
[[ "$pkgline" == *"versionCode='138'"* ]]

adb logcat -c
# A force-stopped app might fail to launch due to a product-level bootstrap issue.
# Keep that result as an explicit failure, never a silent PASS.
set +e
start_result="$(adb shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p com.dsh.android 2>&1)"
start_code=$?
set -e
printf '%s\n' "$start_result" | sed -E 's/(https?:\/\/)[^ ]+/\1[redacted]/g' | head -c 1500
if test "$start_code" -ne 0 || printf '%s\n' "$start_result" | grep -Eqi 'Error:|Exception|not found|unable to resolve'; then
  echo "::error::Android launcher could not start DSH lab candidate"
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
; then
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

adb logcat -c
# A force-stopped app might fail to launch due to a product-level bootstrap issue.
# Keep that result as an explicit failure, never a silent PASS.
set +e
start_result="$(adb shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p com.dsh.android 2>&1)"
start_code=$?
set -e
printf '%s\n' "$start_result" | sed -E 's/(https?:\/\/)[^ ]+/\1[redacted]/g' | head -c 1500
if test "$start_code" -ne 0 || printf '%s\n' "$start_result" | grep -Eqi 'Error:|Exception|not found|unable to resolve'; then
  echo "::error::Android launcher could not start DSH lab candidate"
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
