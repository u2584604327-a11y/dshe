#!/usr/bin/env bash
# P159 disposable Android35 emulator root-ADB reattach, never user phone.
# Return 0 only if independently re-verified QEMU + ranchu/goldfish + booted
# on emulator-5554 with UID=0. Return 1 if transport not ready, 2 unsafe.
p159_verify_disposable_root() {
  local attempts="${P159_MAX_ATTEMPTS:-12}" waitsecs="${P159_WAIT_SECONDS:-3}"
  local sleepsecs="${P159_SLEEP_SECONDS:-1}"
  local n qemu hardware boot uid
  if [[ ! "$attempts" =~ ^[0-9]+$ || ! "$waitsecs" =~ ^[0-9]+$ ||
        ! "$sleepsecs" =~ ^[0-9]+$ ]] ||
     (( attempts<1 || attempts>15 || waitsecs<1 || waitsecs>6 || sleepsecs>2 )); then
    echo P159_CONFIG=INVALID;return 2
  fi
  for ((n=1;n<=attempts;n++)); do
    if timeout "${waitsecs}s" adb -s emulator-5554 wait-for-device >/dev/null 2>&1; then
      qemu="$(timeout 3s adb -s emulator-5554 shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r' || true)"
      hardware="$(timeout 3s adb -s emulator-5554 shell getprop ro.hardware 2>/dev/null | tr -d '\r' || true)"
      boot="$(timeout 3s adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
      uid="$(timeout 3s adb -s emulator-5554 shell id -u 2>/dev/null | tr -d '\r' || true)"
      if [[ -n "$qemu" && "$qemu" != 1 ]]; then
        echo P159_ORIGIN=DENIED_NON_QEMU;return 2
      fi
      if [[ -n "$hardware" ]]; then
        case "$hardware" in ranchu|goldfish) ;; *)
          echo P159_ORIGIN=DENIED_NON_EMULATOR_HARDWARE;return 2;;esac
      fi
      if [[ -n "$uid" && "$uid" != 0 && "$uid" != 2000 ]]; then
        echo P159_UID=DENIED_UNKNOWN;return 2
      fi
      if [[ "$qemu" = 1 && "$hardware" != "" && "$boot" = 1 ]]; then
        if [[ "$uid" = 0 ]]; then
          echo P159_EMULATOR_ROOT=VERIFIED_QEMU_UID_0
          return 0
        fi
        if [[ "$uid" = 2000 ]]; then
          # Transient ADB transport "closed"/"offline" is retryable only
          # after verifying it is the fixed disposable QEMU instance.
          timeout "${waitsecs}s" adb -s emulator-5554 root >/dev/null 2>&1 || true
        fi
      fi
    fi
    if (( n < attempts && sleepsecs > 0 ));then sleep "$sleepsecs";fi
  done
  echo P159_EMULATOR_ROOT=BLOCKED_BOUNDED_ADBD_REATTACH
  return 1
}
