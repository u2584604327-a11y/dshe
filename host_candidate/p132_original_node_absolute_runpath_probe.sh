#!/usr/bin/env bash
# P132: exact signed-v138 original ARM64 Node --version once in disposable offline emulator.
# No original Node ELF changes, no user device, no signing, no tool calls.
set -euo pipefail
stage="$1"
test -s "$stage/bin/node"
test -d "$stage/lib"
remote=/data/local/tmp/dsh-p132-original-node
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
test "$(sha256sum "$stage/bin/node" | awk '{print $1}')" = "$node_sha" || { echo P132_NODE_SHA=INVALID; exit 1; }
test "$(sha256sum "$stage/lib/libcares.so" | awk '{print $1}')" = "$cares_sha" || { echo P132_CARES_SHA=INVALID; exit 1; }
readelf -h "$stage/bin/node" | grep -Eq 'Machine:[[:space:]]*AArch64'
readelf -l "$stage/bin/node" > /dev/null
dynamic_info="$(readelf -d "$stage/bin/node")"
case "$dynamic_info" in
  *"/data/data/com.termux/files/usr/lib"*) echo P132_ORIGINAL_ABSOLUTE_RUNPATH=VERIFIED ;;
  *) echo P132_RUNPATH=DRIFT; exit 1 ;;
esac
echo P132_PINNED_NODE_AND_CARES_SHA256=PASS
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
 static const char m[]="P132_ABSOLUTE_RUNPATH_CARES_OK\n";
 if(write(1,m,sizeof(m)-1)!=sizeof(m)-1) done(32);
 done(0);
}
C
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
test -x "$ndk/clang" || { echo P132_PINNED_NDK=UNAVAILABLE; exit 1; }
"$ndk/clang" --target=aarch64-linux-android35 -fuse-ld=lld -nostdlib \
 -fno-stack-protector -fPIE -pie -Wl,-e,_start \
 -Wl,--dynamic-linker=/system/bin/linker64 \
 -Wl,-rpath,/data/data/com.termux/files/usr/lib \
 "$hosttmp/abs-runpath.c" -Wl,--no-as-needed "$stage/lib/libcares.so" -lc \
 -o "$hosttmp/absolute-runpath"
control_dyn="$(readelf -d "$hosttmp/absolute-runpath")"
case "$control_dyn" in
  *'Library runpath: [/data/data/com.termux/files/usr/lib]'*) ;;
  *) echo P132_ABSOLUTE_CONTROL_RUNPATH=INVALID; exit 1 ;;
esac
case "$control_dyn" in
  *'Shared library: [libcares.so]'*) ;;
  *) echo P132_ABSOLUTE_CONTROL_DT_NEEDED=INVALID; exit 1 ;;
esac
echo P132_ABSOLUTE_CONTROL_ELF_PREFLIGHT=PASS_EXACT_NODE_RUNPATH_AND_CARES_DEP
if test "$P132_COMPILE_ONLY" = 1; then
  echo P132_ANDROID_EXECUTION=NOT_ATTEMPTED_STATIC_ONLY
  exit 0
fi
test "$GITHUB_ACTIONS" = true || { echo P132_GITHUB_CI_ONLY=REFUSED; exit 1; }
timeout 30s adb wait-for-device
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
test "$(adb shell uname -m | tr -d '\r')" = x86_64
case "$(adb shell getprop ro.hardware | tr -d '\r')" in
  ranchu|goldfish) safe=YES ;;
  *) echo P132_NOT_DISPOSABLE_EMULATOR=STOP; exit 1 ;;
esac
test "$(adb shell getprop ro.kernel.qemu | tr -d '\r')" = 1 || {
  echo P132_EMULATOR_KERNEL_PROPERTY=NOT_PROVEN; exit 1;
}
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
case "$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')" in
  libndk_translation.so|libhoudini.so|libhoudini64.so) echo P132_NATIVE_BRIDGE=CONFIGURED ;;
  *) echo P132_NATIVE_BRIDGE=NOT_AVAILABLE; exit 0 ;;
esac
case "$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')" in
  *arm64-v8a*) echo P132_ARM64_GUEST=ADVERTISED ;;
  *) echo P132_ARM64_GUEST=NOT_ADVERTISED; exit 0 ;;
esac
# Refuse any pre-existing Termux directory or installed package; never alter other data.
if test -n "$(adb shell pm path com.termux | tr -d '\r')"; then
  echo P132_TERMUX_INSTALLED=REFUSED; exit 0
fi
if test "$(adb shell "if test -e '$guestroot'; then echo EXISTS; else echo ABSENT; fi" | tr -d '\r')" != ABSENT; then
  echo P132_GUEST_RUNPATH_ALREADY_EXISTS=REFUSED; exit 0
fi
test "$(adb shell getprop ro.debuggable | tr -d '\r')" = 1 || {
  echo P132_DEBUGGABLE_EMULATOR=UNAVAILABLE; exit 0;
}
adb root >/dev/null 2>&1 || {
  echo P132_EMULATOR_ROOT=UNAVAILABLE; exit 0;
}
timeout 30s adb wait-for-device
if test "$(adb shell id -u | tr -d '\r')" != 0; then
  echo P132_EMULATOR_ADBD_ROOT=UNAVAILABLE
  exit 0
fi
echo P132_EMULATOR_ADBD_ROOT=AVAILABLE_FOR_DISPOSABLE_FIXTURE_ONLY
adb shell "mkdir -p '$guestlib' '$remote/bin'" >/dev/null
created=YES
adb push "$stage/lib/." "$guestlib/" >/dev/null
adb push "$stage/bin/node" "$remote/bin/node" >/dev/null
adb push "$hosttmp/absolute-runpath" "$remote/bin/absolute-runpath" >/dev/null
adb shell "chmod 755 '$guestroot' '$guestroot/files' '$guestroot/files/usr' '$guestlib' '$remote' '$remote/bin' '$remote/bin/node' '$remote/bin/absolute-runpath'; chmod 644 '$guestlib'/*" >/dev/null
# Require matching original ELF and representative original library on Android.
test "$(adb shell "sha256sum '$remote/bin/node'" | tr -d '\r' | awk '{print $1}')" = "$node_sha"
test "$(adb shell "sha256sum '$guestlib/libcares.so'" | tr -d '\r' | awk '{print $1}')" = "$cares_sha"
test "$(adb shell "sha256sum '$remote/bin/absolute-runpath'" | tr -d '\r' | awk '{print $1}')" = "$(sha256sum "$hosttmp/absolute-runpath" | awk '{print $1}')"
echo P132_DEVICE_NODE_AND_CARES_SHA256=PASS
# Drop emulator adbd root before attempting Node. Only fixed --version, no scripts.
adb unroot >/dev/null 2>&1
timeout 30s adb wait-for-device
shell_uid="$(adb shell id -u | tr -d '\r')"
if test "$shell_uid" != 2000; then
  echo P132_POST_UNROOT_SHELL_UID=NOT_PROVEN
  exit 0
fi
echo P132_NODE_TEST_UID=ANDROID_ADB_SHELL_2000_NOT_ISOLATED
# Separate synthetic control with EXACT same immutable absolute RUNPATH as original Node.
# This runs under Android shell UID 2000, not root and not the original app.
set +e
control="$(timeout 12s adb shell "env -i PATH=/system/bin:/system/xbin '$remote/bin/absolute-runpath'" 2>&1)"
control_code=$?
set -e
if test "$control_code" = 0 && test "$(printf '%s' "$control" | tr -d '\r\n')" = P132_ABSOLUTE_RUNPATH_CARES_OK; then
  echo P132_ABSOLUTE_RUNPATH_ORIGINAL_CARES=PASS_EXACT_MARKER
else
  echo P132_ABSOLUTE_RUNPATH_ORIGINAL_CARES=BLOCKED
  echo P132_ABSOLUTE_RUNPATH_CONTROL_EXIT="$control_code"
  echo P132_ABSOLUTE_RUNPATH_CONTROL_SHA256="$(printf '%s' "$control" | sha256sum | awk '{print $1}')"
fi
set +e
response="$(timeout 25s adb shell "env -i PATH=/system/bin:/system/xbin '$remote/bin/node' --version" 2>&1)"
code=$?
set -e
line="$(printf '%s' "$response" | tr -d '\r\n')"
if test "$code" = 0 && printf '%s\n' "$line" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo P132_EXACT_ORIGINAL_NODE_VERSION_IN_SHELL=PASS
  echo P132_NODE_VERSION="$line"
else
  echo P132_EXACT_ORIGINAL_NODE_VERSION_IN_SHELL=BLOCKED
  echo P132_NODE_EXIT="$code"
  echo P132_NODE_OUTPUT_SHA256="$(printf '%s' "$response" | sha256sum | awk '{print $1}')"
  reason=UNCLASSIFIED
  if test "$code" = 124; then reason=TIMEOUT
  elif grep -Eqi 'not accessible for the namespace|namespace.*(denied|restricted)' <<< "$response"; then reason=LINKER_NAMESPACE
  elif grep -Eqi 'cannot locate symbol|undefined symbol|relocation.*failed' <<< "$response"; then reason=SYMBOL_RELOCATION
  elif grep -Eqi 'library.*not found|cannot locate library|needed.*not found' <<< "$response"; then reason=LIBRARY_NOT_FOUND
  elif grep -Eqi 'Permission denied|avc: denied' <<< "$response"; then reason=PERMISSION_OR_SELINUX
  elif grep -Eqi 'CANNOT LINK EXECUTABLE|linker.*cannot' <<< "$response"; then reason=ANDROID_LINKER_UNCLASSIFIED
  fi
  echo P132_NODE_ERROR_CLASS="$reason"
  # Fixed allowlist only: names from exact P123 Node DT_NEEDED and known Android baseline.
  # No verbatim stderr, arbitrary symbol or filesystem path is emitted.
  missing=NONE_OF_PINNED_DIRECT_NAMES
  for soname in libz.so.1 libcares.so libsqlite3.so libffi.so libcrypto.so.3 libssl.so.3 libicui18n.so.78 libicuuc.so.78 libc++_shared.so libc.so libm.so libdl.so; do
    if printf '%s' "$response" | grep -Fq "$soname"; then
      missing="$soname"
      break
    fi
  done
  echo P132_DIAGNOSTIC_PINNED_SONAME="$missing"
fi
echo P132_ORIGINAL_ISOLATED_UID=NOT_TESTED
echo P132_ENGINE_MANAGER_LIFECYCLE=NOT_TESTED
echo P132_P109_SENSITIVE_TOOL_AUTHORITY=DENY_ALL
echo P132_FORMAL_V139_RELEASE=BLOCKED
