#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/p164_emulator_screen_preflight.sh"
export ANDROID_SERIAL=emulator-5554
p164_qemu=1
p164_boot=1
p164_abi=x86_64
p164_api=36
p164_deny_wake=0
p164_deny_dismiss=0
p164_commands=()
adb(){
  p164_commands+=("$*")
  case "$*" in
    'shell getprop ro.kernel.qemu') printf '%s\n' "$p164_qemu";;
    'shell getprop sys.boot_completed') printf '%s\n' "$p164_boot";;
    'shell getprop ro.product.cpu.abi') printf '%s\n' "$p164_abi";;
    'shell getprop ro.build.version.sdk') printf '%s\n' "$p164_api";;
    'shell input keyevent KEYCODE_WAKEUP') [[ "$p164_deny_wake" == 0 ]];;
    'shell wm dismiss-keyguard') [[ "$p164_deny_dismiss" == 0 ]];;
    *) echo "P164_UNEXPECTED_ADB_ACTION=DENIED" >&2;return 1;;
  esac
}
p164_count_actions(){
  local a n=0
  for a in "${p164_commands[@]}";do
    if [[ "$a" == 'shell input keyevent KEYCODE_WAKEUP' ||
          "$a" == 'shell wm dismiss-keyguard' ]];then ((n+=1));fi
  done
  [[ "$n" == "$1" ]]
}
out="$(p164_prepare_disposable_emulator_ui 36)"
[[ "$out" == *'P164_QEMU_BOOT_ABI_API_EXACT_ATTESTATION=PASS'* &&
   "$out" == *'P164_NATIVE_WINDOW_FOCUS=STILL_REQUIRED_BEFORE_CONSENT'* ]] || exit 1
# Subshell command substitutions cannot observe array mutations. Use a
# direct invocation for exact device action accounting.
p164_commands=()
p164_prepare_disposable_emulator_ui 36 >/dev/null
p164_count_actions 2 || { echo P164_MOCK_WRONG_ACTION_COUNT=FAIL;exit 1; }
expect_deny(){
  local label="$1";shift
  p164_commands=()
  if p164_prepare_disposable_emulator_ui "$@" >/dev/null;then
    echo "P164_FAIL_OPEN=$label";exit 1;
  fi
  p164_count_actions 0 || {
    if [[ "$label" != WAKE_DENIED && "$label" != DISMISS_DENIED ]];then
      echo P164_UNVERIFIED_DEVICE_OS_ACTION=FAIL;exit 1;
    fi
  }
}
ANDROID_SERIAL=physical-test expect_deny SERIAL 36
p164_qemu=0;expect_deny NON_QEMU 36;p164_qemu=1
p164_boot=0;expect_deny NOT_BOOTED 36;p164_boot=1
p164_abi=arm64-v8a;expect_deny WRONG_ABI 36;p164_abi=x86_64
p164_api=35;expect_deny WRONG_API 36;p164_api=36
expect_deny API_NOT_ALLOWED 37
p164_deny_wake=1;expect_deny WAKE_DENIED 36;p164_deny_wake=0
p164_deny_dismiss=1;expect_deny DISMISS_DENIED 36;p164_deny_dismiss=0
echo P164_EXACT_EMULATOR_QEMU_BOOT_ABI_API_DENY_TESTS=PASS
echo P164_NO_APP_CONSENT_OR_PRODUCTION_DEVICE_ACTIONS=PASS
