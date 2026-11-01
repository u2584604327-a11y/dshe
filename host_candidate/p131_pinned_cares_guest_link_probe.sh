#!/usr/bin/env bash
# P131: exact SHA-pinned v138 ARM64 c-ares, synthetic app only; no original Node exec.
set -euo pipefail
stage="$1"
test -f "$stage/lib/libcares.so"
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
test -x "$ndk/clang" || { echo P131_NDK=UNAVAILABLE; exit 1; }
export PATH="$ndk:$PATH"
tmp="$(mktemp -d)"
remote=/data/local/tmp/dsh-p131-cares
safe=NO
adb() { command adb -s emulator-5554 "$@"; }
cleanup() { if test "$safe" = YES; then adb shell "rm -rf '$remote'" >/dev/null 2>&1 || true; fi; rm -rf -- "$tmp"; }
trap cleanup EXIT
readelf -h "$stage/lib/libcares.so" | grep -Eq 'Machine:[[:space:]]*AArch64'
readelf --dyn-syms --wide "$stage/lib/libcares.so" > "$tmp/cares-dynsym.txt"
grep -Eq '[[:space:]]ares_version(@@?[^[:space:]]+)?([[:space:]]|$)' "$tmp/cares-dynsym.txt" || { echo P131_ARES_EXPORT=NOT_FOUND; exit 1; }
echo P131_ARES_EXPORT=PASS_DETERMINISTIC_NO_PIPE
soname="$(readelf -d "$stage/lib/libcares.so" | sed -n 's/.*(SONAME).*Shared library: \[\([^]]*\)\].*/\1/p' | head -1)"
test -n "$soname" || soname=libcares.so
case "$soname" in libcares.so|libcares.so.[0-9]|libcares.so.[0-9][0-9]) ;; *) echo P131_CARES_SONAME=UNSAFE; exit 1 ;; esac
cat > "$tmp/probe.c" <<'C'
#include <stddef.h>
extern long write(int,const void*,size_t);
#ifdef PINNED
extern const char *ares_version(int *);
#endif
__attribute__((noreturn)) static void done(long code) {
 register long x0 __asm__("x0")=code;
 register long x8 __asm__("x8")=93;
 __asm__ volatile("svc #0" :: "r"(x0),"r"(x8) : "memory");
 __builtin_unreachable();
}
void _start(void) {
#ifdef PINNED
 if (!ares_version((int*)0)) done(31);
 static const char msg[]="P131_CARES_OK\n";
#else
 static const char msg[]="P131_LIBC_OK\n";
#endif
 if(write(1,msg,sizeof(msg)-1)!=sizeof(msg)-1) done(32);
 done(0);
}
C
args=(--target=aarch64-linux-android35 -fuse-ld=lld -nostdlib -fno-stack-protector -fPIE -pie -Wl,-e,_start -Wl,--dynamic-linker=/system/bin/linker64)
clang "${args[@]}" "$tmp/probe.c" -lc -o "$tmp/platform"
clang "${args[@]}" -DPINNED "$tmp/probe.c" -Wl,--no-as-needed "$stage/lib/libcares.so" -lc -o "$tmp/pinned"
for b in platform pinned; do
 readelf -h "$tmp/$b" | grep -Eq 'Machine:[[:space:]]*AArch64'
 readelf -l "$tmp/$b" | grep -Fq '[Requesting program interpreter: /system/bin/linker64]'
 readelf -d "$tmp/$b" | grep -Fq '[libc.so]'
done
readelf -d "$tmp/pinned" | grep -Fq "[$soname]" || { echo P131_DT_NEEDED=NOT_PINNED; exit 1; }
if readelf -d "$tmp/platform" | grep -Fq "[$soname]"; then exit 1; fi
echo P131_PREFLIGHT=PASS_TRUE_LIBC_AND_REAL_CARES_DT_NEEDED
echo P131_CARES_SHA256="$(sha256sum "$stage/lib/libcares.so" | awk '{print $1}')"
if test "$P131_COMPILE_ONLY" = 1; then echo P131_DEVICE=NOT_TESTED_COMPILE_ONLY; exit 0; fi
test "$GITHUB_ACTIONS" = true
timeout 30s adb wait-for-device
case "$(adb shell getprop ro.hardware | tr -d '\r')" in ranchu|goldfish) safe=YES ;; *) echo P131_DEVICE=REFUSED_NON_EMULATOR; exit 1 ;; esac
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
test "$(adb shell uname -m | tr -d '\r')" = x86_64
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
case "$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')" in libndk_translation.so|libhoudini.so|libhoudini64.so) ;; *) echo P131_BRIDGE=UNAVAILABLE; exit 0 ;; esac
case "$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')" in *arm64-v8a*) ;; *) echo P131_GUEST_ABI=NOT_ADVERTISED; exit 0 ;; esac
adb shell "mkdir -p '$remote/lib'" >/dev/null
for b in platform pinned; do
 adb push "$tmp/$b" "$remote/$b" >/dev/null
 adb shell "chmod 700 '$remote/$b'" >/dev/null
 test "$(sha256sum "$tmp/$b" | awk '{print $1}')" = "$(adb shell "sha256sum '$remote/$b'" | tr -d '\r' | awk '{print $1}')"
done
echo P131_DEVICE_ELF_SHA=PASS
check() {
 lbl="$1"; commandline="$2"; expected="$3"
 set +e
 output="$(timeout 12s adb shell "$commandline" 2>&1)"
 code=$?
 set -e
 if test "$code" = 0 && test "$(printf '%s' "$output" | tr -d '\r\n')" = "$expected"; then
   printf 'P131_%s=PASS_EXACT_MARKER\n' "$lbl"; return 0
 fi
 printf 'P131_%s=BLOCKED\nP131_%s_EXIT=%s\n' "$lbl" "$lbl" "$code"
 printf 'P131_%s_OUTPUT_SHA256=%s\n' "$lbl" "$(printf '%s' "$output" | sha256sum | awk '{print $1}')"
 return 1
}
libc=NO; cares=NO
check LIBC_PLATFORM "'$remote/platform'" P131_LIBC_OK && libc=YES
if check MISSING_CARES "'$remote/pinned'" P131_CARES_OK; then
 echo P131_NEGATIVE_CONTROL=FAIL_UNEXPECTED_PREEXISTING_SONAME
 exit 1
fi
echo P131_NEGATIVE_CONTROL=PASS_NO_UNEXPECTED_SUCCESS
adb push "$stage/lib/libcares.so" "$remote/lib/$soname" >/dev/null
test "$(sha256sum "$stage/lib/libcares.so" | awk '{print $1}')" = "$(adb shell "sha256sum '$remote/lib/$soname'" | tr -d '\r' | awk '{print $1}')"
echo P131_REAL_LIB_DEVICE_SHA=PASS
check EXACT_CARES "LD_LIBRARY_PATH='$remote/lib' '$remote/pinned'" P131_CARES_OK && cares=YES
if test "$libc" = YES && test "$cares" = YES; then
 echo P131_GUEST_LINKER=PASS_LIBC_AND_REAL_CARES
elif test "$libc" = YES; then
 echo P131_GUEST_LINKER=BLOCKED_ORIGINAL_CARES_RESOLUTION
else
 echo P131_GUEST_LINKER=BLOCKED_BIONIC_PLATFORM
fi
echo P131_ORIGINAL_NODE=NOT_EXECUTED
echo P131_ISOLATED_UID=NOT_TESTED
echo P131_P109_AUTHORITY=DENY_ALL
echo P131_RELEASE_V139=BLOCKED
