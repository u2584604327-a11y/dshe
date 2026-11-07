#!/usr/bin/env bash
# Native ARM64 hosted-runner feasibility only, with ZERO downloads/licenses.
set -euo pipefail
output() {
  printf '%s\n' "$1"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]];then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}
[[ "${GITHUB_ACTIONS:-}" = true ]] || { output P160_CI_ONLY=DENIED;exit 2; }
[[ "${GITHUB_REPOSITORY:-}" = u2584604327-a11y/dshe ]] || {
  output P160_REPOSITORY_GUARD=DENIED;exit 2;
}
[[ "$(uname -s)" = Linux && "$(uname -m)" = aarch64 ]] || {
  output P160_REAL_ARM64_HOST=DENIED_NOT_NATIVE;exit 2;
}
output P160_REAL_ARM64_LINUX_HOST=PASS_UNAME_AARCH64
# P160_KVM is an actual harmless KVM_GET_API_VERSION+KVM_CREATE_VM
# check; it creates no guest CPU and starts no Android image.
python3 host_candidate/p160_arm64_native_runner/p160_arm64_kvm_probe.py |
  while IFS= read -r row;do output "$row";done
sdk=""
for candidate in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" /usr/local/lib/android/sdk /opt/android-sdk;do
  if [[ -n "$candidate" && -d "$candidate" ]];then sdk="$candidate";break;fi
done
if [[ -z "$sdk" ]];then
  output P160_ANDROID_SDK=NOT_PREINSTALLED
  output P160_ARM64_ANDROID_IMAGE=NOT_PREINSTALLED
else
  output P160_ANDROID_SDK=PREINSTALLED_DIRECTORY
  emulator="$sdk/emulator/emulator"
  if [[ -x "$emulator" ]];then
    if command -v readelf >/dev/null &&
       readelf -h "$emulator" 2>/dev/null | grep -Eq 'Machine:.*AArch64';then
      output P160_ANDROID_EMULATOR=ARM64_ELF_PREINSTALLED
    else
      output P160_ANDROID_EMULATOR=PREINSTALLED_ARCH_UNVERIFIED
    fi
  else
    output P160_ANDROID_EMULATOR=NOT_PREINSTALLED
  fi
  img="$sdk/system-images/android-35/google_apis/arm64-v8a"
  if [[ -f "$img/source.properties" ]] &&
     find "$img" -maxdepth 1 -type f -name '*.img' -print -quit | grep -q .;then
    output P160_ARM64_ANDROID_IMAGE=PREINSTALLED_METADATA_AND_IMAGE
  else
    output P160_ARM64_ANDROID_IMAGE=NOT_PREINSTALLED
  fi
fi
output P160_LICENSE_ACCEPTANCE=NOT_ATTEMPTED
output P160_ANDROID_GUEST_KERNEL_AARCH64=NOT_TESTED
output P160_ANDROID_APP_ISOLATED_UID=NOT_TESTED
output P160_ORIGINAL_V138_NODE_AND_ENGINEMANAGER=NOT_EXECUTED
output P160_ORIGINAL_HTTP_READY=NOT_TESTED
output P160_P109_SENSITIVE_TOOLS=DENY_ALL
output P160_FORMAL_V139=BLOCKED
