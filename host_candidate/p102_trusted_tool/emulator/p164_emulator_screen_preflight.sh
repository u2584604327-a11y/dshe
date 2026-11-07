#!/usr/bin/env bash
# P164: prepare the UI of a VERIFIED, ephemeral Android 35/36 QEMU emulator.
# This never approves any native consent, never uses any app data, and refuses
# physical devices, non-x86 native ARM64, nonbooted Android or ambiguous ADB.
p164_prepare_disposable_emulator_ui(){
  local expected_api="$1" kernel_emu boot abi sdk
  [[ "${ANDROID_SERIAL:-}" == emulator-5554 ]] || {
    echo P164_ADB_SERIAL_NOT_EXACT_EMULATOR=DENIED;return 1;
  }
  [[ "$expected_api" == 35 || "$expected_api" == 36 ]] || {
    echo P164_ANDROID_API_NOT_ALLOWED=DENIED;return 1;
  }
  kernel_emu="$(adb shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r')" || return 1
  boot="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" || return 1
  abi="$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')" || return 1
  sdk="$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')" || return 1
  if [[ "$kernel_emu" != 1 || "$boot" != 1 ||
        "$abi" != x86_64 || "$sdk" != "$expected_api" ]];then
    echo P164_DISPOSABLE_EMULATOR_ATTESTATION=DENIED;return 1
  fi
  echo P164_QEMU_BOOT_ABI_API_EXACT_ATTESTATION=PASS
  # Non-consent Android OS wake / non-secure keyguard dismiss requests.
  # The subsequent P161/P162 real native window focus and Binder-generation
  # gates still govern the ONLY allowed synthetic approval button click.
  adb shell input keyevent KEYCODE_WAKEUP >/dev/null || {
    echo P164_EMULATOR_WAKE_REQUEST=DENIED;return 1;
  }
  adb shell wm dismiss-keyguard >/dev/null || {
    echo P164_NONSECURE_KEYGUARD_DISMISS_REQUEST=DENIED;return 1;
  }
  echo P164_WAKE_AND_NONSECURE_KEYGUARD_DISMISS_REQUESTED=PASS_REQUEST_ONLY
  echo P164_NATIVE_WINDOW_FOCUS=STILL_REQUIRED_BEFORE_CONSENT
}
