#!/usr/bin/env bash
# P130: disposable offline emulator only; synthetic ARM64 ELF, no DSH or original Node.
set -euo pipefail
root="$(mktemp -d)"
remote=/data/local/tmp/dsh-p130-elf-control
safe=NO
adb() { command adb -s emulator-5554 "$@"; }
cleanup() {
  if test "$safe" = YES; then adb shell "rm -rf '$remote'" >/dev/null 2>&1 || true; fi
  rm -rf -- "$root"
}
trap cleanup EXIT
cat > "$root/probe.S" <<'ASM'
.section .rodata
msg:
#ifdef P130_STATIC
.ascii "P130_ARM64_STATIC_OK\n"
#else
.ascii "P130_ARM64_DYNAMIC_OK\n"
#endif
.set msglen, . - msg
.section .text
.global _start
_start:
 mov x0, #1
 adr x1, msg
 mov x2, #msglen
 mov x8, #64
 svc #0
 mov x0, #0
 mov x8, #93
 svc #0
ASM
for t in clang ld.lld readelf sha256sum; do command -v "$t" >/dev/null; done
clang --target=aarch64-linux-android35 -fuse-ld=lld -nostdlib -static -Wl,-e,_start -DP130_STATIC "$root/probe.S" -o "$root/arm64-static"
clang --target=aarch64-linux-android35 -fuse-ld=lld -nostdlib -pie -Wl,-e,_start -Wl,--dynamic-linker=/system/bin/linker64 "$root/probe.S" -o "$root/arm64-dynamic"
for f in "$root/arm64-static" "$root/arm64-dynamic"; do
  readelf -h "$f" | grep -Eq 'Machine:[[:space:]]*AArch64'
done
if readelf -l "$root/arm64-static" | grep -q INTERP; then exit 1; fi
readelf -l "$root/arm64-dynamic" | grep -Fq '[Requesting program interpreter: /system/bin/linker64]'
if readelf -d "$root/arm64-dynamic" | grep -q '(NEEDED)'; then exit 1; fi
echo P130_ELF_PREFLIGHT=PASS_ARM64_STATIC_AND_DYNAMIC_NO_NEEDED
if test "$P130_COMPILE_ONLY" = 1; then
  echo P130_ANDROID_EXECUTION=NOT_ATTEMPTED_COMPILE_ONLY
  exit 0
fi
test "$GITHUB_ACTIONS" = true || { echo P130_CI_ONLY=REFUSED; exit 1; }
timeout 30s adb wait-for-device
hardware="$(adb shell getprop ro.hardware | tr -d '\r')"
case "$hardware" in ranchu|goldfish) safe=YES ;; *) echo P130_NOT_DISPOSABLE_EMULATOR=STOP; exit 1 ;; esac
test "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1
test "$(adb shell uname -m | tr -d '\r')" = x86_64
adb shell cmd connectivity airplane-mode enable >/dev/null
adb shell svc wifi disable >/dev/null || true
adb shell svc data disable >/dev/null || true
test "$(adb shell settings get global airplane_mode_on | tr -d '\r')" = 1
bridge="$(adb shell getprop ro.dalvik.vm.native.bridge | tr -d '\r')"
abis="$(adb shell getprop ro.product.cpu.abilist | tr -d '\r')"
case "$bridge" in libndk_translation.so|libhoudini.so|libhoudini64.so) echo P130_BRIDGE=CONFIGURED ;; *) echo P130_BRIDGE=NOT_PROVEN; exit 0 ;; esac
case "$abis" in *arm64-v8a*) echo P130_ARM64_ABI=ADVERTISED ;; *) echo P130_ARM64_ABI=NOT_ADVERTISED; exit 0 ;; esac
for h in arm64_exe arm64_dyn; do
  v="$(adb shell "if test -r /proc/sys/fs/binfmt_misc/$h; then echo PRESENT; else echo NOT_OBSERVED; fi" | tr -d '\r')"
  case "$v" in PRESENT|NOT_OBSERVED) ;; *) v=UNCLASSIFIED ;; esac
  echo "P130_BINFMT_$h=$v"
done
adb shell "mkdir -p '$remote'" >/dev/null
for k in static dynamic; do
  adb push "$root/arm64-$k" "$remote/arm64-$k" >/dev/null
  adb shell "chmod 700 '$remote/arm64-$k'"
  lhs="$(sha256sum "$root/arm64-$k" | awk '{print $1}')"
  rhs="$(adb shell "sha256sum '$remote/arm64-$k'" | tr -d '\r' | awk '{print $1}')"
  test "$lhs" = "$rhs" || { echo P130_DEVICE_SHA=FAIL; exit 1; }
done
echo P130_DEVICE_SHA=PASS
run_probe() {
  label="$1"
  marker="$2"
  set +e
  output="$(timeout 12s adb shell "'$remote/arm64-$label'" 2>&1)"
  exit_code=$?
  set -e
  value="$(printf '%s' "$output" | tr -d '\r\n')"
  if test "$exit_code" = 0 && test "$value" = "$marker"; then
    echo "P130_$label=PASS_EXACT_MARKER"
    return 0
  fi
  echo "P130_$label=BLOCKED"
  echo "P130_$label"_EXIT="$exit_code"
  echo "P130_$label"_REDACTED_SHA256="$(printf '%s' "$output" | sha256sum | awk '{print $1}')"
  return 1
}
s=NO; d=NO
run_probe static P130_ARM64_STATIC_OK && s=YES
run_probe dynamic P130_ARM64_DYNAMIC_OK && d=YES
if test "$s" = YES && test "$d" = YES; then
  echo P130_DISPATCH=PASS_STATIC_AND_NO_NEEDED_DYNAMIC
elif test "$s" = YES; then
  echo P130_DISPATCH=STATIC_PASS_DYNAMIC_GUEST_LINK_OR_POLICY_UNPROVEN
elif test "$d" = YES; then
  echo P130_DISPATCH=DYNAMIC_PASS_STATIC_PATH_UNPROVEN
else
  echo P130_DISPATCH=NOT_PROVEN
fi
echo P130_ORIGINAL_NODE=NOT_EXECUTED
echo P130_ISOLATED_UID=NOT_TESTED
echo P130_P109_NATIVE_AUTHORITY=DENY_ALL
echo P130_V139_RELEASE=BLOCKED
