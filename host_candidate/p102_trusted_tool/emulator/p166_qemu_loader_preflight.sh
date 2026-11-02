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
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
  local binary="$sdk/emulator/qemu/linux-x86_64/qemu-system-x86_64"
  local before="${RUNNER_TEMP:-}/p166-qemu-ldd-before.txt"
  local after="${RUNNER_TEMP:-}/p166-qemu-ldd-after.txt"
  [[ -n "${RUNNER_TEMP:-}" && -x "$binary" && ! -L "$binary" ]] || {
    echo P166_PINNED_QEMU_BINARY_UNAVAILABLE=DENIED;return 3;
  }
  ldd "$binary" > "$before" || {
    echo P166_QEMU_LDD_BEFORE=DENIED;return 3;
  }
  local state=0
  p166_classify_missing "$before" || state=$?
  case "$state" in
    0) echo P166_QEMU_LOADER=ALREADY_CLOSED;return 0;;
    2) ;;
    *) echo P166_QEMU_LOADER_UNEXPECTED_MISSING=DENIED;return 3;;
  esac
  # Ephemeral GitHub runner only, exact Ubuntu distribution package.
  # No --yes-license, no Android sdkmanager, no user data or APK.
  if ! grep -q '^ID=ubuntu$' /etc/os-release ||
     ! grep -q '^VERSION_ID="24.04"$' /etc/os-release;then
    echo P166_UNSUPPORTED_RUNNER_DISTRIBUTION=DENIED;return 3
  fi
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -qq update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get -y -qq install --no-install-recommends libpulse0
  ldd "$binary" > "$after" || {
    echo P166_QEMU_LDD_AFTER=DENIED;return 3;
  }
  state=0
  p166_classify_missing "$after" || state=$?
  [[ "$state" == 0 ]] || {
    echo P166_GRAPHICAL_QEMU_LOADER_STILL_INCOMPLETE=DENIED;return 3;
  }
  echo P166_LIBPULSE_RUNTIME_REPAIRED_ON_EPHEMERAL_CI=PASS
  echo P166_NATIVE_APPROVAL_AND_PRODUCTION_APK=UNTOUCHED
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]];then
  p166_prepare_qemu_loader
fi
