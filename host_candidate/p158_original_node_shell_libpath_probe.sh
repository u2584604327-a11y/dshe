#!/usr/bin/env bash
# P158: alternate READABLE /data/local/tmp library search path on a disposable
# offline x86_64 Native Bridge emulator, never on user's DSH or phone.
# Complements, never replaces, P155 original hardcoded RUNPATH test.
p158_error_class() {
  local message="$1" code="$2"
  if [[ "$code" = 124 ]]; then echo TIMEOUT
  elif grep -Eqi 'not accessible for the namespace|namespace.*(denied|restricted)' <<< "$message"; then echo LINKER_NAMESPACE
  elif grep -Eqi 'cannot locate symbol|undefined symbol|relocation.*failed' <<< "$message"; then echo SYMBOL_RELOCATION
  elif grep -Eqi 'library.*not found|cannot locate library|needed.*not found' <<< "$message"; then echo LIBRARY_NOT_FOUND
  elif grep -Eqi 'Permission denied|avc: denied' <<< "$message"; then echo PERMISSION_OR_SELINUX
  elif grep -Eqi 'Exec format error|cannot execute.*format' <<< "$message"; then echo EXEC_FORMAT_OR_NATIVE_BRIDGE
  elif grep -Eqi 'CANNOT LINK EXECUTABLE|linker.*cannot' <<< "$message"; then echo ANDROID_LINKER_UNCLASSIFIED
  else echo UNCLASSIFIED; fi
}
p158_shell_alt_loader_probe() {
  local stage="$1" remote="/data/local/tmp/dsh-p132-original-node"
  local guest_lib="$remote/lib"
  local name expected raw observed status rc response code line
  [[ "${GITHUB_ACTIONS:-}" = true ]] || { echo P158_CI_ONLY=DENIED;return 2; }
  [[ "$remote" = "/data/local/tmp/dsh-p132-original-node" ]] || return 2
  [[ "$(timeout 6s adb -s emulator-5554 shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r')" = 1 ]] || {
    echo P158_EMULATOR_ATTESTATION=DENIED; return 2;
  }
  [[ "$(timeout 6s adb -s emulator-5554 shell id -u 2>/dev/null | tr -d '\r')" = 2000 ]] || {
    echo P158_SHELL_UID_NOT_2000=DENIED;return 2;
  }
  [[ "$(timeout 6s adb -s emulator-5554 shell getprop ro.product.cpu.abilist 2>/dev/null | tr -d '\r')" = *arm64-v8a* ]] || {
    echo P158_ARM64_NATIVE_BRIDGE_NOT_ADVERTISED=DENIED;return 2;
  }
  echo P158_UID=ADB_SHELL_2000_NOT_ORIGINAL_APP_OR_ISOLATED
  # Exact original ELF and nine library names already staged under the
  # fixed scratch root. Refuse execution on any unverified guest byte.
  expected="a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6"
  raw="$(timeout 10s adb -s emulator-5554 shell "sha256sum '$remote/bin/node'" 2>/dev/null || true)"
  observed="${raw%%[[:space:]]*}"
  if [[ "$observed" != "$expected" ]]; then echo P158_NODE_SHELL_SHA=INVALID;return 2;fi
  for name in libz.so.1 libcares.so libsqlite3.so libffi.so libcrypto.so.3 libssl.so.3 libicui18n.so.78 libicuuc.so.78 libc++_shared.so; do
    [[ -f "$stage/lib/$name" ]] || { echo P158_SOURCE_LIBRARY_MISSING=DENIED;return 2; }
    expected="$(sha256sum "$stage/lib/$name" | awk '{print $1}')"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo P158_SOURCE_SHA_INVALID=DENIED;return 2; }
    raw="$(timeout 10s adb -s emulator-5554 shell "sha256sum '$guest_lib/$name'" 2>/dev/null || true)"
    observed="${raw%%[[:space:]]*}"
    if [[ "$expected" != "$observed" ]]; then
      echo P158_GUEST_LIBRARY_PROVENANCE=UNVERIFIED_NO_EXEC
      return 2
    fi
  done
  echo P158_GUEST_9_PINNED_LIBRARIES_AND_NODE_SHELL_SHA=PASS
  # This intentionally uses LD_LIBRARY_PATH in the shell-readable SCRATCH
  # directory; it does NOT assert the original absolute Termux RUNPATH works.
  # env is empty except fixed system PATH and the explicit scratch lib path.
  if response="$(timeout 25s adb -s emulator-5554 shell "env -i PATH=/system/bin:/system/xbin LD_LIBRARY_PATH='$guest_lib' '$remote/bin/node' --version" 2>&1)";then
    code=0
  else code=$?;fi
  line="$(printf '%s' "$response" | tr -d '\r\n')"
  if [[ "$code" = 0 ]] && [[ "$line" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo P158_EXACT_ORIGINAL_NODE_VERSION_WITH_SCRATCH_LD_LIBRARY_PATH=PASS
    echo "P158_NODE_VERSION=$line"
  else
    echo P158_EXACT_ORIGINAL_NODE_VERSION_WITH_SCRATCH_LD_LIBRARY_PATH=BLOCKED
    echo "P158_NODE_EXIT=$code"
    echo "P158_ERROR_CLASS=$(p158_error_class "$response" "$code")"
    echo "P158_OUTPUT_SHA256=$(printf '%s' "$response" | sha256sum | awk '{print $1}')"
  fi
  echo P158_ORIGINAL_TERMUX_HARDCODED_RUNPATH_VERIFIED=NO
  echo P158_CORRECT_APP_UID_OR_ISOLATED_WORKER=NOT_TESTED
  echo P158_PRODUCTION_ENGINEMANAGER_HTTP_READY=NOT_TESTED
  echo P158_P109_NATIVE_TOOL_AUTHORITY=DENY_ALL
  echo P158_V139_RELEASE=BLOCKED
  return 0
}
