#!/usr/bin/env bash
# P127: an OFFLINE, disposable Google APIs emulator test of exact original Node.
# Only adb shell's UID is tested, never Android isolated Service or user phone.
set -euo pipefail
staged="$1"
test -s "$staged/bin/node"
test -d "$staged/lib"
adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1"
adb shell cmd connectivity airplane-mode enable
adb shell svc wifi disable || true
adb shell svc data disable || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = "1"
arch="$(adb shell uname -m | tr -d '\r')"
abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
bridge="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
exec_flag="$(adb shell getprop ro.enable.native.bridge.exec | tr -d '\r')"
echo "P127_GOOGLE_APIS_KERNEL_ARCH=$arch"
if test "$arch" != x86_64; then
  echo 'P127_UNEXPECTED_SYSTEM_IMAGE_CPU=BLOCKED'
  exit 1
fi
case "$abis" in
  *arm64-v8a*) has_arm64=YES ;;
  *) has_arm64=NO ;;
esac
echo "P127_GOOGLE_APIS_ARM64_ABI_ADVERTISED=$has_arm64"
case "$bridge" in
  ""|"0"|"none") native=NO ;;
  "libndk_translation.so"|"libhoudini.so"|"libhoudini64.so") native=YES ;;
  *) native=UNVERIFIED ;;
esac
echo "P127_GOOGLE_APIS_NATIVE_BRIDGE_CONFIGURED=$native"
case "$exec_flag" in
  "1"|"true") echo 'P127_NATIVE_BRIDGE_EXEC_PROP=ON_UNVERIFIED' ;;
  *) echo 'P127_NATIVE_BRIDGE_EXEC_PROP=OTHER_OR_DISABLED' ;;
esac
binfmt="$(adb shell 'if test -r /proc/sys/fs/binfmt_misc/arm64_exe; then echo ARM64_EXE_REGISTERED; else echo ARM64_EXE_NOT_OBSERVED; fi' | tr -d '\r')"
echo "P127_BINFMT_ARM64_EXEC=$binfmt"
echo 'P127_ORIGINAL_ARM64_NODE_ISOLATED_UID=NOT_TESTED'
echo 'P127_P109_TOOL_ACCESS=DENY_ALL'
if test "$native" != YES || test "$has_arm64" != YES; then
  echo 'P127_ORIGINAL_ARM64_NODE_VERSION=NOT_ATTEMPTED_NATIVE_BRIDGE_UNAVAILABLE'
  exit 0
fi

# Fixed path ONLY in disposable emulator; no user APK/phone, credentials or model.
remote=/data/local/tmp/dsh-p127-original-node-probe
cleanup() { adb shell "rm -rf $remote" >/dev/null 2>&1 || true; }
trap cleanup EXIT
adb shell "mkdir -p $remote/bin $remote/lib"
adb push "$staged/bin/node" "$remote/bin/node" >/dev/null
adb push "$staged/lib/." "$remote/lib/" >/dev/null
adb shell "chmod 700 $remote/bin/node"
digest="$(adb shell "sha256sum $remote/bin/node" | tr -d '\r' | awk '{print $1}')"
if test "$digest" != a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6; then
  echo '::error::P127 original Node SHA drifted during ADB staging'
  exit 1
fi
echo 'P127_ORIGINAL_ARM64_ELF_DEVICE_SHA256=PASS'
# Hard timeout on the ADB invocation. Output is inspected locally and NEVER
# printed verbatim; no Node scripts, network, shell command from the model.
set +e
response="$(timeout 20s adb shell "LD_LIBRARY_PATH=$remote/lib $remote/bin/node --version" 2>&1)"
code=$?
set -e
clean="$(printf '%s' "$response" | tr -d '\r\n')"
if test "$code" -eq 0 && printf '%s\n' "$clean" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "P127_ORIGINAL_ARM64_NODE_VERSION_IN_EMULATOR_SHELL=PASS"
  echo "P127_ORIGINAL_ARM64_NODE_VERSION=$clean"
  echo 'P127_ORIGINAL_ARM64_NODE_IN_ISOLATED_APP=NOT_TESTED'
else
  # No verbatim stderr/stdout, user data, paths or environment is logged.
  # A fixed exit code and bounded output digest preserve reproducible evidence.
  echo "P127_NODE_REMOTE_EXIT_CODE=$code"
  diagnostic_digest="$(printf '%s' "$response" | sha256sum | awk '{print $1}')"
  echo "P127_NODE_REDACTED_OUTPUT_SHA256=$diagnostic_digest"
  referenced=NONE_OF_PINNED_DIRECT_LIBRARIES
  for lib in libz.so.1 libcares.so libsqlite3.so libffi.so libcrypto.so.3 libssl.so.3 libicui18n.so.78 libicuuc.so.78 libc++_shared.so libc.so libm.so libdl.so; do
    if printf '%s' "$response" | grep -Fq "$lib"; then
      referenced="$lib"
      break
    fi
  done
  echo "P127_DIAGNOSTIC_REFERENCED_NEEDED_LIBRARY=$referenced"
  # P127 exact-cause contract: emit ONLY literal categories, no raw linker
  # text, symbols, filesystem paths, environment, device account state or secrets.
  # Priority matters: namespace and symbol errors often include the generic
  # "CANNOT LINK EXECUTABLE" string, which is not a root-cause diagnosis.
  if test "$code" -eq 124; then
    failure=TIMEOUT
  elif printf '%s\\n' "$response" | grep -Eqi 'not accessible for the namespace|not permitted in (the )?namespace|library namespace|namespace.*(denied|restricted)'; then
    failure=ANDROID_LINKER_NAMESPACE_DENIED
  elif printf '%s\\n' "$response" | grep -Eqi 'cannot locate symbol|undefined symbol|cannot find symbol|symbol.*not found|relocation.*failed'; then
    failure=ELF_SYMBOL_OR_RELOCATION_UNRESOLVED
  elif printf '%s\\n' "$response" | grep -Eqi 'library.*not found|cannot find library|cannot locate library|shared object.*not found|needed.*not found'; then
    failure=UNRESOLVED_DYNAMIC_LIBRARY
  elif printf '%s\\n' "$response" | grep -Eqi 'wrong ELF class|unexpected e_machine|invalid ELF|exec format|architecture mismatch'; then
    failure=ELF_ARCH_FORMAT_INCOMPATIBLE
  elif printf '%s\\n' "$response" | grep -Eqi 'Permission denied|access denied|not permitted|avc: denied'; then
    failure=EXEC_PERMISSION_OR_SELINUX
  elif printf '%s\\n' "$response" | grep -Eqi 'CANNOT LINK EXECUTABLE|linker.*failed|linker.*cannot'; then
    failure=ANDROID_DYNAMIC_LINKER_UNCLASSIFIED
  elif printf '%s\\n' "$response" | grep -Eqi 'No such file|not found'; then
    failure=MISSING_RUNTIME_PATH_UNCLASSIFIED
  else
    failure=UNKNOWN_FAIL_CLOSED
  fi
  echo "P127_LOADER_ROOT_CAUSE_CLASS=$failure"
  echo "P127_ORIGINAL_ARM64_NODE_VERSION_IN_EMULATOR_SHELL=BLOCKED_$failure"
  # A/B, not a retry of the same failed environment. Some native-bridge
  # emulator launchers are x86_64 processes: their host loader may incorrectly
  # encounter guest ARM64 .so files when LD_LIBRARY_PATH points to the guest
  # directory. Run exactly ONE system-library-only control on the same pinned
  # ELF, with no shell scripts, tooling or user data, and do not disclose raw
  # stdout/stderr. This does NOT bypass Android linker namespaces.
  if test "$failure" = ANDROID_DYNAMIC_LINKER_UNCLASSIFIED; then
    set +e
    control="$(timeout 20s adb shell "LD_LIBRARY_PATH=/system/lib64:/system/lib $remote/bin/node --version" 2>&1)"
    control_code=$?
    set -e
    echo "P127_SYSTEM_LIBS_ONLY_EXIT_CODE=$control_code"
    echo "P127_SYSTEM_LIBS_ONLY_OUTPUT_SHA256=$(printf '%s' "$control" | sha256sum | awk '{print $1}')"
    cleaned="$(printf '%s' "$control" | tr -d '\\r\\n')"
    if test "$control_code" -eq 0 && printf '%s' "$cleaned" | grep -Eq '^v[0-9]+\\.[0-9]+\\.[0-9]+$'; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=PASS_SHELL_UID_NOT_ISOLATED'
      echo "P127_SYSTEM_LIBS_ONLY_VERSION=$cleaned"
    elif test "$control_code" -eq 124; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_TIMEOUT'
    elif printf '%s' "$control" | grep -Eqi 'not accessible for the namespace|namespace.*denied'; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_NAMESPACE'
    elif printf '%s' "$control" | grep -Eqi 'cannot locate symbol|undefined symbol|relocation.*failed'; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_SYMBOL'
    elif printf '%s' "$control" | grep -Eqi 'library.*not found|cannot locate library|needed.*not found'; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_MISSING_LIBRARY'
    elif printf '%s' "$control" | grep -Eqi 'CANNOT LINK EXECUTABLE|linker'; then
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_LINKER_UNCLASSIFIED'
    else
      echo 'P127_SYSTEM_LIBS_ONLY_NODE_VERSION=BLOCKED_OTHER'
    fi
    echo 'P127_AB_COMPARISON_DISTINCT_LIBRARY_ENVIRONMENTS=YES'
  else
    echo 'P127_AB_COMPARISON=SKIPPED_NOT_GENERIC_LINKER_FAILURE'
  fi
  echo 'P127_ORIGINAL_NODE_EXEC_PRODUCTION=NOT_PROVEN'
fi
echo 'P127_ORIGINAL_ARM64_NODE_IN_ISOLATED_APP=NOT_TESTED'
