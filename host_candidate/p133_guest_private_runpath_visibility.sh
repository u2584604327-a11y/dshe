#!/usr/bin/env bash
# P133: only synthetic ELF dynamic-loader controls and non-root shell file visibility.
# No original Node execution, no user device, no signing, no tool calls.
set -euo pipefail
stage="$1"
test -s "$stage/bin/node"
test -d "$stage/lib"
remote=/data/local/tmp/dsh-p133-runpath-visibility
guestroot=/data/data/com.termux
guestlib=/data/data/com.termux/files/usr/lib
hosttmp="$(mktemp -d)"
node_sha=a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6
cares_sha=68733ce8d4bb1bdc87d8ec550c58c70f3dcdb0f8c48d86b83235f536cb736e83
adb() { command adb -s emulator-5554 "$@"; }
safe=NO
created=NO
cleanup() {
  rm -rf -- "$hosttmp"
  if test "$safe" = YES; then
    adb root >/dev/null 2>&1 || true
    adb wait-for-device >/dev/null 2>&1 || true
    adb shell "rm -rf '$remote'" >/dev/null 2>&1 || true
    if test "$created" = YES; then
      adb shell "rm -rf '$guestroot'" >/dev/null 2>&1 || true
    fi
    adb unroot >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
test "$(sha256sum "$stage/bin/node" | awk '{print $1}')" = "$node_sha" || { echo P133_NODE_SHA=INVALID; exit 1; }
test "$(sha256sum "$stage/lib/libcares.so" | awk '{print $1}')" = "$cares_sha" || { echo P133_CARES_SHA=INVALID; exit 1; }
readelf -h "$stage/bin/node" | grep -Eq 'Machine:[[:space:]]*AArch64'
readelf -l "$stage/bin/node" > /dev/null
dynamic_info="$(readelf -d "$stage/bin/node")"
case "$dynamic_info" in
  *"/data/data/com.termux/files/usr/lib"*) echo P133_ORIGINAL_ABSOLUTE_RUNPATH=VERIFIED ;;
  *) echo P133_RUNPATH=DRIFT; exit 1 ;;
esac
echo P133_PINNED_NODE_AND_CARES_SHA256=PASS
cat > "$hosttmp/abs-runpath.c" <<'C'
#include <stddef.h>
extern long write(int, const void *, size_t);
extern const char *ares_version(int *);
__attribute__((noreturn)) static void done(long code) {
 register long x0 __asm__("x0")=code;
 register long x8 __asm__("x8")=93;
 __asm__ volatile("svc #0" :: "r"(x0),"r"(x8) : "memory");
 __builtin_unreachable();
}
void _start(void) {
 if (!ares_version((int*)0)) done(31);
 static const char m[]="P133_ABSOLUTE_RUNPATH_CARES_OK\n";
 if(write(1,m,sizeof(m)-1)!=sizeof(m)-1) done(32);
 done(0);
}
C
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
test -x "$ndk/clang" || { echo P133_PINNED_NDK=UNAVAILABLE; exit 1; }
"$ndk/clang" --target=aarch64-linux-android35 -fuse-ld=lld -nostdlib \
 -fno-stack-protector -fPIE -pie -Wl,-e,_start \
 -Wl,--dynamic-linker=/system/bin/linker64 \
 -Wl,-rpath,/data/data/com.termux/files/usr/lib \
 "$hosttmp/abs-runpath.c" -Wl,--no-as-needed "$stage/lib/libcares.so" -lc \
 -o "$hosttmp/absolute-runpath"
"$ndk/clang" --target=aarch64-linux-android35 -fuse-ld=lld -nostdlib \
 -fno-stack-protector -fPIE -pie -Wl,-e,_start \
 -Wl,--dynamic-linker=/system/bin/linker64 \
 '-Wl,-rpath,$ORIGIN/lib' \
 "$hosttmp/abs-runpath.c" -Wl,--no-as-needed "$stage/lib/libcares.so" -lc \
 -o "$hosttmp/origin-runpath"
origin_dyn="$(readelf -d "$hosttmp/origin-runpath")"
case "$origin_dyn" in
  *'Library runpath: [$ORIGIN/lib]'*) ;;
  *) echo P133_ORIGIN_CONTROL_RUNPATH=INVALID; exit 1 ;;
esac
case "$origin_dyn" in
  *'Shared library: [libcares.so]'*) ;;
  *) echo P133_ORIGIN_CONTROL_NEEDED=INVALID; exit 1 ;;
esac
echo P133_ORIGIN_CONTROL_ELF_PREFLIGHT=PASS
control_dyn="$(readelf -d "$hosttmp/absolute-runpath")"
case "$control_dyn" in
  *'Library runpath: [/data/data/com.termux/files/usr/lib]'*) ;;
  *) echo P133_ABSOLUTE_CONTROL_RUNPATH=INVALID; exit 1 ;;
esac
case "$control_dyn" in
  *'Shared library: [libcares.so]'*) ;;
  *) echo P133_ABSOLUTE_CONTROL_DT_NEEDED=INVALID; exit 1 ;;
esac
echo P133_ABSOLUTE_CONTROL_ELF_PREFLIGHT=PASS_EXACT_NODE_RUNPATH_AND_CARES_DEP
if test "$P133_COMPILE_ONLY" = 1; then
  echo P133_ANDROID_EXECUTION=NOT_ATTEMPTED_STATIC_ONLY
  exit 0
fi
test "$GITHUB_ACTIONS" = true || { echo P133_GITHUB_CI_ONLY=REFUSED; exit 1; }
timeout 30s adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
test "$(adb shell uname -m | tr -d '\r')" = x86_64
case "$(adb shell getprop ro.hardware | tr -d '\r')" in
  ranchu|goldfish) safe=YES ;;
  *) echo P133_NOT_DISPOSABLE_EMULATOR=STOP; exit 1 ;;
esac
test "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1 || {
  echo P133_EMULATOR_KERNEL_PROPERTY=NOT_PROVEN; exit 1;
}
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
case "$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')" in
  libndk_translation.so|libhoudini.so|libhoudini64.so) echo P133_NATIVE_BRIDGE=CONFIGURED ;;
  *) echo P133_NATIVE_BRIDGE=NOT_AVAILABLE; exit 0 ;;
esac
case "$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')" in
  *arm64-v8a*) echo P133_ARM64_GUEST=ADVERTISED ;;
  *) echo P133_ARM64_GUEST=NOT_ADVERTISED; exit 0 ;;
esac
# Refuse any pre-existing Termux directory or installed package; never alter other data.
if test -n "$(adb shell pm path com.termux | tr -d '\r')"; then
  echo P133_TERMUX_INSTALLED=REFUSED; exit 0
fi
if test "$(adb shell "if test -e '$guestroot'; then echo EXISTS; else echo ABSENT; fi" | tr -d '\r')" != ABSENT; then
  echo P133_GUEST_RUNPATH_ALREADY_EXISTS=REFUSED; exit 0
fi
test "$(adb shell getprop ro.debuggable | tr -d '\r')" = 1 || {
  echo P133_DEBUGGABLE_EMULATOR=UNAVAILABLE; exit 0;
}
adb root >/dev/null 2>&1 || {
  echo P133_EMULATOR_ROOT=UNAVAILABLE; exit 0;
}
timeout 30s adb wait-for-device
if test "$(adb shell id -u | tr -d '\r')" != 0; then
  echo P133_EMULATOR_ADBD_ROOT=UNAVAILABLE
  exit 0
fi
echo P133_EMULATOR_ADBD_ROOT=AVAILABLE_FOR_DISPOSABLE_FIXTURE_ONLY
adb shell "mkdir -p '$guestlib' '$remote/bin/lib'" >/dev/null
created=YES
adb push "$stage/lib/libcares.so" "$guestlib/libcares.so" >/dev/null
adb push "$stage/lib/libcares.so" "$remote/bin/lib/libcares.so" >/dev/null
adb push "$hosttmp/absolute-runpath" "$remote/bin/absolute-runpath" >/dev/null
adb push "$hosttmp/origin-runpath" "$remote/bin/origin-runpath" >/dev/null
adb shell "chmod 755 '$guestroot' '$guestroot/files' '$guestroot/files/usr' '$guestlib' '$remote' '$remote/bin' '$remote/bin/lib' '$remote/bin/absolute-runpath' '$remote/bin/origin-runpath'; chmod 644 '$guestlib'/* '$remote/bin/lib/libcares.so'" >/dev/null
# Require matching original ELF and representative original library on Android.
test "$(adb shell "sha256sum '$remote/bin/lib/libcares.so'" | tr -d '\r' | awk '{print $1}')" = "$cares_sha"
test "$(adb shell "sha256sum '$guestlib/libcares.so'" | tr -d '\r' | awk '{print $1}')" = "$cares_sha"
test "$(adb shell "sha256sum '$remote/bin/absolute-runpath'" | tr -d '\r' | awk '{print $1}')" = "$(sha256sum "$hosttmp/absolute-runpath" | awk '{print $1}')"
test "$(adb shell "sha256sum '$remote/bin/origin-runpath'" | tr -d '\r' | awk '{print $1}')" = "$(sha256sum "$hosttmp/origin-runpath" | awk '{print $1}')"
echo P133_DEVICE_CARES_AND_SYNTHETIC_SHA=PASS
# Drop emulator adbd root before running *synthetic* AArch64 controls.
# Fail closed on UID ambiguity; never run a probe as root.
if adb unroot >/dev/null 2>&1; then
  echo P133_ADB_UNROOT_COMMAND=ACCEPTED
else
  echo P133_ADB_UNROOT_COMMAND=NONZERO_RECHECK_IDENTITY
fi
if ! timeout 30s adb wait-for-device; then
  echo P133_SHELL_UID_POST_UNROOT=UNKNOWN_STOP
  exit 0
fi
shell_uid="$(adb shell id -u 2>/dev/null | tr -d '\r')" || {
  echo P133_SHELL_UID_POST_UNROOT=UNKNOWN_STOP
  exit 0
}
if test "$shell_uid" != 2000; then
  echo P133_POST_UNROOT_SHELL_UID=NOT_PROVEN
  exit 0
fi
echo P133_TEST_UID=ANDROID_SHELL_2000_NOT_ISOLATED
# Only exact fixed private-path fixtures created on this disposable emulator.
for directory in "$guestroot" "$guestroot/files" "$guestroot/files/usr" "$guestlib"; do
  if adb shell "test -x '$directory'" >/dev/null 2>&1; then
    echo P133_PRIVATE_DIRECTORY_TRAVERSE=PASS
  else
    echo P133_PRIVATE_DIRECTORY_TRAVERSE=DENIED
  fi
done
if adb shell "test -r '$guestlib/libcares.so'" >/dev/null 2>&1; then
  echo P133_PRIVATE_LIBRARY_READ_TEST=PASS
else
  echo P133_PRIVATE_LIBRARY_READ_TEST=DENIED
fi
# Actual read, not test -r (which may only check Unix mode bits).
set +e
hash_output="$(timeout 12s adb shell "sha256sum '$guestlib/libcares.so'" 2>&1)"
hash_code=$?
set -e
hash_first="$(printf '%s' "$hash_output" | tr -d '\r' | awk 'NR==1 {print $1}')"
if test "$hash_code" = 0 && test "$hash_first" = "$cares_sha"; then
  echo P133_SHELL_PRIVATE_LIBRARY_BYTES=PASS_EXACT_SHA
else
  echo P133_SHELL_PRIVATE_LIBRARY_BYTES=BLOCKED
  echo P133_SHELL_PRIVATE_LIBRARY_READ_EXIT="$hash_code"
  cls=UNCLASSIFIED
  if test "$hash_code" = 124; then cls=TIMEOUT
  elif grep -Eqi 'Permission denied|access denied|avc: denied' <<< "$hash_output"; then cls=ACCESS_DENIED
  elif grep -Eqi 'No such file or directory|not found' <<< "$hash_output"; then cls=PATH_NOT_FOUND
  elif test "$hash_code" = 0 && printf '%s' "$hash_first" | grep -Eq '^[0-9a-f]{64}
for mode in origin absolute; do
  if test "$mode" = origin; then path="$remote/bin/origin-runpath"; else path="$remote/bin/absolute-runpath"; fi
  set +e
  output="$(timeout 12s adb shell "env -i PATH=/system/bin:/system/xbin '$path'" 2>&1)"
  code=$?
  set -e
  if test "$code" = 0 && test "$(printf '%s' "$output" | tr -d '\r\n')" = P133_ABSOLUTE_RUNPATH_CARES_OK; then
    printf 'P133_%s_GUEST_LOADER=PASS_EXACT_MARKER\n' "$mode"
  else
    printf 'P133_%s_GUEST_LOADER=BLOCKED\n' "$mode"
    printf 'P133_%s_EXIT=%s\n' "$mode" "$code"
    printf 'P133_%s_OUTPUT_SHA256=%s\n' "$mode" "$(printf '%s' "$output" | sha256sum | awk '{print $1}')"
    category=UNCLASSIFIED
    if grep -Eqi 'not accessible for the namespace|namespace.*(denied|restricted)' <<< "$output"; then category=NAMESPACE_DENIED
    elif grep -Eqi 'library.*not found|cannot locate library|needed.*not found' <<< "$output"; then category=LIBRARY_NOT_FOUND
    elif grep -Eqi 'Permission denied|avc: denied' <<< "$output"; then category=ACCESS_DENIED
    elif grep -Eqi 'undefined symbol|cannot locate symbol|relocation.*failed' <<< "$output"; then category=SYMBOL_RELOCATION
    fi
    printf 'P133_%s_ERROR_CLASS=%s\n' "$mode" "$category"
  fi
done
echo P133_ORIGINAL_NODE_EXECUTED=NO
echo P133_ANDROID_ISOLATED_UID=NOT_TESTED
echo P133_P109_NATIVE_AUTHORITY=DENY_ALL
echo P133_FORMAL_V139_RELEASE=BLOCKED
; then cls=HASH_MISMATCH
  fi
  echo P133_SHELL_PRIVATE_LIBRARY_READ_CLASS="$cls"
  echo P133_SHELL_PRIVATE_LIBRARY_READ_OUTPUT_SHA="$(printf '%s' "$hash_output" | sha256sum | awk '{print $1}')"
fi
enforce="$(adb shell getenforce 2>/dev/null | tr -d '\r')"
case "$enforce" in Enforcing|Permissive|Disabled) echo P133_SELINUX_MODE="$enforce" ;; *) echo P133_SELINUX_MODE=UNKNOWN ;; esac
label_info="$(adb shell "ls -Zd '$guestlib/libcares.so'" 2>&1 || true)"
case "$label_info" in
  *app_data_file*) echo P133_ORIGINAL_PRIVATE_LIB_SELINUX_LABEL=APP_DATA_FILE ;;
  *shell_data_file*) echo P133_ORIGINAL_PRIVATE_LIB_SELINUX_LABEL=SHELL_DATA_FILE ;;
  *system_data_file*) echo P133_ORIGINAL_PRIVATE_LIB_SELINUX_LABEL=SYSTEM_DATA_FILE ;;
  *Permission\ denied*) echo P133_ORIGINAL_PRIVATE_LIB_SELINUX_LABEL=LABEL_ACCESS_DENIED ;;
  *) echo P133_ORIGINAL_PRIVATE_LIB_SELINUX_LABEL=OTHER_OR_UNAVAILABLE ;;
esac
for mode in origin absolute; do
  if test "$mode" = origin; then path="$remote/bin/origin-runpath"; else path="$remote/bin/absolute-runpath"; fi
  set +e
  output="$(timeout 12s adb shell "env -i PATH=/system/bin:/system/xbin '$path'" 2>&1)"
  code=$?
  set -e
  if test "$code" = 0 && test "$(printf '%s' "$output" | tr -d '\r\n')" = P133_ABSOLUTE_RUNPATH_CARES_OK; then
    printf 'P133_%s_GUEST_LOADER=PASS_EXACT_MARKER\n' "$mode"
  else
    printf 'P133_%s_GUEST_LOADER=BLOCKED\n' "$mode"
    printf 'P133_%s_EXIT=%s\n' "$mode" "$code"
    printf 'P133_%s_OUTPUT_SHA256=%s\n' "$mode" "$(printf '%s' "$output" | sha256sum | awk '{print $1}')"
    category=UNCLASSIFIED
    if grep -Eqi 'not accessible for the namespace|namespace.*(denied|restricted)' <<< "$output"; then category=NAMESPACE_DENIED
    elif grep -Eqi 'library.*not found|cannot locate library|needed.*not found' <<< "$output"; then category=LIBRARY_NOT_FOUND
    elif grep -Eqi 'Permission denied|avc: denied' <<< "$output"; then category=ACCESS_DENIED
    elif grep -Eqi 'undefined symbol|cannot locate symbol|relocation.*failed' <<< "$output"; then category=SYMBOL_RELOCATION
    fi
    printf 'P133_%s_ERROR_CLASS=%s\n' "$mode" "$category"
  fi
done
echo P133_ORIGINAL_NODE_EXECUTED=NO
echo P133_ANDROID_ISOLATED_UID=NOT_TESTED
echo P133_P109_NATIVE_AUTHORITY=DENY_ALL
echo P133_FORMAL_V139_RELEASE=BLOCKED
