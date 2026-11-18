#!/usr/bin/env bash
# P301: synthetic isolated UID reliable-pipe read-stage diagnosis. No network.
set -euo pipefail
cd "$(dirname "$0")/../.."
serial=emulator-5554
pkg=com.dsh.p301probe
apk=host_candidate/p301_android35_fd_diag/probe/.p301-disposable.apk
installed=NO
cleanup(){
  if [[ "$installed" == YES ]];then
    adb -s "$serial" shell am force-stop "$pkg" >/dev/null 2>&1 || true
    adb -s "$serial" uninstall "$pkg" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
[[ "$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$serial" shell getprop ro.build.version.sdk | tr -d '\r\n')" == 35 ]]
[[ "$(adb -s "$serial" shell getprop ro.product.cpu.abi | tr -d '\r\n')" == x86_64 ]]
[[ -s "$apk" && -n "${ANDROID_HOME:-}" ]]
[[ "$(adb -s "$serial" shell pm list packages "$pkg" | tr -d '\r')" != *"package:$pkg"* ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.p301probe'"* &&
   "$badging" != *"uses-permission:"* ]]
adb -s "$serial" install "$apk" >/dev/null
installed=YES
marker="P301_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P301_RUN_[0-9a-f]{24}$ ]]
adb -s "$serial" shell log -p i -t P301_BOUNDARY "$marker" >/dev/null
adb -s "$serial" shell am start -W -n "$pkg/.ProbeActivity" >/dev/null
selected=''
for _ in $(seq 1 35);do
  raw="$(adb -s "$serial" logcat -d -v brief -s P301_BOUNDARY:I P301_HOST:I P301_WORKER:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){n++;live=1;next}
    live{print}
    END{if(n!=1)print "P301_BOUNDARY_INVALID"}
  ')"
  if [[ "$selected" == *P301_BOUNDARY_INVALID* ]];then
    echo P301_DIAG_BOUNDARY_INVALID=DENY;exit 2
  fi
  # Logcat may contain context: only print these literal categories, never values.
  for category in \
    READ_EOF_PEER_DEAD READ_EOF_PEER_LEAKED READ_EOF_DETACHED \
    READ_EOF_REMOTE_ERROR READ_IO_EOF_CHECK READ_IO_PARTIAL READ_IO_ZERO \
    READ_SECURITY READ_RUNTIME \
    EARLY_EOF EXTRA_BYTES BAD_FRAME DESCRIPTOR_OPEN WORKER_REPLAY \
    BAD_SENDER BAD_PARCEL REPLY_TARGET_GONE \
    REPLY_IDENTITY REPLY_PARCEL WORKER_FAILURE UNEXPECTED_REPLY \
    INITIAL_SEND DISCONNECTED HOST_PIPE_IO RESTORED_STATE BIND_SERVICE;do
    if [[ "$selected" == *"P301_DENY_$category=DENY"* ]];then
      echo "P301_DIAG_$category=DENY"
      for witness in P301_WORKER_DESCRIPTOR_RECEIVED P301_WORKER_EXACT_LENGTH_READ P301_WORKER_CONTENT_MATCHED P301_WORKER_CLEAN_EOF P301_HOST_FD_SENT P301_HOST_WRITE_COMPLETE;do
        if [[ "$selected" == *"$witness=PASS"* ]];then
          echo "$witness=PASS"
        fi
      done
      exit 2
    fi
  done
  if [[ "$selected" == *"=DENY"* ]];then
    echo P301_DIAG_UNEXPECTED_CATEGORY=DENY;exit 2
  fi
  if [[ "$selected" == *"P301_HOST_FD_RECEIPT=PASS"* ]];then break;fi
  sleep 1
done
for key in P301_MISSING_FD_DENIED P301_MISSING_FD_REJECTED \
  P301_WORKER_DESCRIPTOR_RECEIVED P301_HOST_FD_SENT \
  P301_HOST_WRITE_COMPLETE P301_WORKER_EXACT_LENGTH_READ \
  P301_WORKER_CONTENT_MATCHED P301_WORKER_CLEAN_EOF \
  P301_HOST_FD_RECEIPT;do
  n="$(printf '%s\n' "$selected" | grep -Fc "$key=PASS" || true)"
  [[ "$n" == 1 ]] || { echo P301_REQUIRED_MARKER_COUNT=DENY;exit 2; }
done
printf '%s\n' "$selected" | awk '
/P301_MISSING_FD_DENIED=PASS/{a=NR}
/P301_MISSING_FD_REJECTED=PASS/{b=NR}
/P301_WORKER_DESCRIPTOR_RECEIVED=PASS/{c=NR}
/P301_WORKER_EXACT_LENGTH_READ=PASS/{d=NR}
/P301_WORKER_CONTENT_MATCHED=PASS/{e=NR}
/P301_WORKER_CLEAN_EOF=PASS/{f=NR}
/P301_HOST_FD_RECEIPT=PASS/{g=NR}
END{if(!(a>0&&b>a&&c>b&&d>c&&e>d&&f>e&&g>f))exit 2}' || {
  echo P301_REQUIRED_ORDER=DENY;exit 2;
}
echo P301_ANDROID35_HOST_TO_ISOLATED_FD=PASS
echo P301_REAL_ANDROID_FRAMEWORK_UID_CHECK=PASS
echo P301_SYNTHETIC_PIPE_READ_AND_CLEAN_EOF=PASS
echo P301_ORIGINAL_NODE_FD_INTEGRATION=NOT_WIRED
echo P301_ORIGINAL_P245=UNCHANGED
echo P301_P192_LOOPBACK_BIND_EACCES=STILL_BLOCKED
echo P301_USER_DEVICE_AND_DATA=NOT_TOUCHED
echo P301_V139_RELEASE=STRUCTURAL_BLOCKED
