#!/usr/bin/env bash
# P166: repair ONLY the precisely observed missing libpulse runtime dependency
# of the disposable Android36 GRAPHICAL QEMU executable on a GitHub hosted
# Ubuntu runner. Not an APK, SDK license, physical phone or consent change.
set -euo pipefail

p166_classify_missing(){
  local report="$1" missing rest
  [[ -f "$report" && ! -L "$report" ]] || return 3
  missing="$(awk '$2=="=>" && $3=="not" && $4=="found" {print $1}' "$report" | sort -u)"
  if [[ -z "$missing" ]];then
    echo P166_GRAPHICAL_QEMU_REQUIRED_LIBRARIES=CLOSED
    return 0
  fi
  if [[ "$missing" != "libpulse.so.0" ]];then
    echo P166_GRAPHICAL_QEMU_UNEXPECTED_MISSING_LIBRARY=DENIED
    return 4
  fi
  echo P166_GRAPHICAL_QEMU_MISSING_LIBPULSE=CONFIRMED
  return 2
}

p166_prepare_qemu_loader(){
  if [[ "${GITHUB_ACTIONS:-}" != true ||
        "${GITHUB_REPOSITORY:-}" != u2584604327-a11y/dshe ||
        "${RUNNER_OS:-}" != Linux ]];then
    echo P166_NON_CI_OR_FOREIGN_REPO=DENIED;return 3
  fi
  # reactivecircus/android-emulator-runner installs emulator binaries INSIDE
  # its subsequent step, so a pre-step cannot require the QEMU ELF yet.
  if ! grep -q '^ID=ubuntu$' /etc/os-release ||
     ! grep -q '^VERSION_ID="24.04"$' /etc/os-release;then
    echo P166_UNSUPPORTED_RUNNER_DISTRIBUTION=DENIED;return 3
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
  local binary="$sdk/emulator/qemu/linux-x86_64/qemu-system-x86_64"
  local state=0 before="${RUNNER_TEMP:-}/p166-qemu-ldd-before.txt"
  [[ -n "${RUNNER_TEMP:-}" ]] || { echo P166_RUNNER_TEMP_REQUIRED=DENIED;return 3; }
  if [[ -x "$binary" ]];then
    ldd "$binary" > "$before" || {
      echo P166_QEMU_LDD_BEFORE=DENIED;return 3;
    }
    p166_classify_missing "$before" || state=$?
    case "$state" in
      0) echo P166_QEMU_LOADER_ALREADY_CLOSED=PASS;;
      2) ;;
      *) echo P166_QEMU_LOADER_UNEXPECTED_MISSING=DENIED;return 3;;
    esac
  else
    echo P166_QEMU_ELF_STAGED_BY_ANDROID_EMULATOR_ACTION_LATER=YES
  fi
  # The actual prior graphical QEMU failure identified libpulse.so.0.
  # One exact Ubuntu runtime package, transient runner only. Never Android
  # sdkmanager --licenses, mobile devices, original APK or native approval.
  local libs="${RUNNER_TEMP}/p166-ldconfig.txt"
  ldconfig -p > "$libs" || {
    echo P166_LDCONFIG_UNAVAILABLE=DENIED;return 3;
  }
  if ! grep -Eq '[[:space:]]libpulse\.so\.0[[:space:]]' "$libs";then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get -qq update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get -y -qq install --no-install-recommends libpulse0
    ldconfig -p > "$libs" || {
      echo P166_LDCONFIG_AFTER_INSTALL=DENIED;return 3;
    }
  fi
  if ! grep -Eq '[[:space:]]libpulse\.so\.0[[:space:]]' "$libs";then
    echo P166_LIBPULSE_RUNTIME_NOT_FOUND=DENIED;return 3
  fi
  echo P166_LIBPULSE_RUNTIME_AVAILABLE_BEFORE_EMULATOR_RUNNER=PASS
  echo P166_QEMU_LOADER_FULL_CLOSURE_CHECK=REQUIRED_AFTER_EMULATOR_BOOT
}

# Proves the original SDK QEMU process truly runs under the same
# GitHub CI kernel AND the emulator guest is boot-complete. A standalone
# ldd can report SDK bundled libs unavailable outside the launcher env.
p166_require_live_booted_qemu(){
  local binary="$1" exact ex p pid found=0 boot
  [[ -x "$binary" ]] || return 1
  exact="$(readlink -f "$binary")" || return 1
  [[ -n "$exact" ]] || return 1
  for p in /proc/[0-9]*/exe;do
    ex="$(readlink -f "$p" 2>/dev/null || true)"
    [[ "$ex" == "$exact" ]] || continue
    pid="${p#/proc/}";pid="${pid%/exe}"
    if kill -0 "$pid" 2>/dev/null;then
      found=1
      break
    fi
  done
  if [[ "$found" != 1 ]];then
    echo P166_EXACT_LIVE_QEMU_PROCESS=NOT_FOUND
    return 1
  fi
  boot="$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" || return 1
  [[ "$boot" == 1 ]] || {
    echo P166_ANDROID_GUEST_BOOT_COMPLETED=NO;return 1;
  }
  echo P166_EXACT_LIVE_QEMU_PROCESS=PASS
  echo P166_ANDROID_GUEST_BOOT_COMPLETED=PASS
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]];then
  p166_prepare_qemu_loader
fi
