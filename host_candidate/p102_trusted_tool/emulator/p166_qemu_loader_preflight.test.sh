#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/p166_qemu_loader_preflight.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf 'linux-vdso.so.1 (0x0000)\nlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x0000)\n' > "$tmp/closed"
printf 'libpulse.so.0 => not found\n' > "$tmp/pulse"
printf 'libpulse.so.0 => not found\nlibfake.so.7 => not found\n' > "$tmp/unknown"
out="$(p166_classify_missing "$tmp/closed")"
[[ "$out" == *'P166_GRAPHICAL_QEMU_REQUIRED_LIBRARIES=CLOSED'* ]]
expect_rc(){
  local expected="$1" file="$2" out rc
  set +e
  out="$(p166_classify_missing "$file")"
  rc=$?
  set -e
  [[ "$rc" == "$expected" ]] || {
    echo "P166_UNSAFE_CLASSIFIER_ACCEPTED=$file";exit 1;
  }
}
expect_rc 2 "$tmp/pulse"
expect_rc 4 "$tmp/unknown"
expect_rc 3 "$tmp/missing"
# Environment denial is proved WITHOUT calling sudo or apt-get.
set +e
out="$(env -u GITHUB_ACTIONS bash "$(dirname "$0")/p166_qemu_loader_preflight.sh" 2>&1)"
code=$?
set -e
[[ "$code" -ne 0 && "$out" == *'P166_NON_CI_OR_FOREIGN_REPO=DENIED'* ]]
echo P166_CLOSED_PULSE_UNKNOWN_AND_NON_CI_NEGATIVES=PASS
# Confirm the helper does not mistakenly require a preinstalled QEMU ELF.
grep -Fq 'P166_QEMU_ELF_STAGED_BY_ANDROID_EMULATOR_ACTION_LATER=YES' "$(dirname "$0")/p166_qemu_loader_preflight.sh"
grep -Fq 'P166_QEMU_POSTBOOT_FULL_LOADER_DEPENDENCIES=PASS' "$(dirname "$0")/run_emulator_e2e.sh"
# Live QEMU proof must explicitly refuse missing binary without booting.
if p166_require_live_booted_qemu "$tmp/not-a-qemu" >/dev/null 2>&1;then
  echo P166_LIVE_QEMU_MISSING_BINARY_FALSE_PASS=FAIL;exit 1
fi
grep -Fq 'p166_require_live_booted_qemu "$qemu_binary"' "$(dirname "$0")/run_emulator_e2e.sh"
echo P166_LIVE_QEMU_AND_BOOT_REQUIRED_AFTER_ACTION=PASS
echo P166_EMULATOR_ACTION_STAGING_ORDER_REGRESSION=PASS
echo P166_NO_PACKAGE_INSTALL_IN_UNIT_TEST=YES
