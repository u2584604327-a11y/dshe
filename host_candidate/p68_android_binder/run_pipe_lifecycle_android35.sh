#!/usr/bin/env bash
# Native Android Parcel/PFD EOF regression only; no Node, original app or Binder UID claim.
set -euo pipefail
cd "$(dirname "$0")/../.."
[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REPOSITORY:-}" == u2584604327-a11y/dshe ]]
serial="${1:?emulator serial required}"
apk="${2:?disposable APK required}"
[[ "$serial" =~ ^emulator-[0-9]+$ && "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]]
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r\n')" == 35 ]]
[[ "$(adb -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r\n')" == x86_64 ]]
[[ -s "$apk" && -s .p68pipetmp/classes.dex ]]
remote="/data/local/tmp/p68-owned-pipe-${GITHUB_RUN_ID}"
cleanup(){
  adb -s "$serial" shell rm -f "$remote.dex" "$remote.apk" >/dev/null 2>&1 || true
}
trap cleanup EXIT
adb -s "$serial" push .p68pipetmp/classes.dex "$remote.dex" >/dev/null
adb -s "$serial" push "$apk" "$remote.apk" >/dev/null
adb -s "$serial" shell chmod 644 "$remote.dex" "$remote.apk"
adb -s "$serial" shell su 2000 dalvikvm -Xverify:all -cp "$remote.dex:$remote.apk" \
  com.dsh.android.p68.P68ReliablePipeLifecycleTest | tr -d '\r' | tee .p68pipetmp/android-result.txt
for marker in \
  P68_OLD_COMPLETE_STREAM_EOF_FALSE_CANCEL=REPRODUCED \
  P68_RELIABLE_STDIN_EOF_NO_FALSE_CANCEL=PASS \
  P68_OLD_WRITER_COPY_MASKED_ERROR=REPRODUCED \
  P68_RELIABLE_WRITER_ERROR_AND_PEER_LOSS_STILL_DENIED=PASS \
  P68_FIXTURE_BINDER_IDENTITY_AND_ARM64_NODE=NOT_ATTESTED;do
  grep -Fxq "$marker" .p68pipetmp/android-result.txt
done
grep -Eq '^P68_ANDROID35_RELIABLE_PIPE_OWNERSHIP=PASS checks=[1-9][0-9]*$' .p68pipetmp/android-result.txt
