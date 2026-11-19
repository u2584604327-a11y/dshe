#!/usr/bin/env bash
# P302: synthetic isolated UID reliable-pipe read-stage diagnosis. No network.
set -euo pipefail
cd "$(dirname "$0")/../.."
serial=emulator-5554
pkg=com.dsh.p302probe
apk=host_candidate/p302_android35_fd_stream/probe/.p302-disposable.apk
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
[[ "$badging" == *"package: name='com.dsh.p302probe'"* &&
   "$badging" != *"uses-permission:"* ]]
adb -s "$serial" install "$apk" >/dev/null
installed=YES
marker="P302_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P302_RUN_[0-9a-f]{24}$ ]]
adb -s "$serial" shell log -p i -t P302_BOUNDARY "$marker" >/dev/null
adb -s "$serial" shell am start -W -n "$pkg/.ProbeActivity" >/dev/null
selected=''
for _ in $(seq 1 35);do
  raw="$(adb -s "$serial" logcat -d -v brief -s P302_BOUNDARY:I P302_HOST:I P302_WORKER:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){n++;live=1;next}
    live{print}
    END{if(n!=1)print "P302_BOUNDARY_INVALID"}
  ')"
  if [[ "$selected" == *P302_BOUNDARY_INVALID* ]];then
    echo P302_DIAG_BOUNDARY_INVALID=DENY;exit 2
  fi
  # Logcat may contain context: only print these literal categories, never values.
  for category in \
    READ_EOF_PEER_DEAD READ_EOF_PEER_LEAKED READ_EOF_DETACHED \
    READ_EOF_REMOTE_ERROR READ_IO_EOF_CHECK READ_IO_PARTIAL READ_IO_ZERO \
    READ_SECURITY READ_RUNTIME \
    EARLY_EOF EXTRA_BYTES BAD_FRAME DESCRIPTOR_OPEN WORKER_REPLAY \
    BAD_SENDER BAD_PARCEL REPLY_TARGET_GONE \
    REPLY_IDENTITY REPLY_PARCEL WORKER_FAILURE UNEXPECTED_REPLY \
    INITIAL_SEND REPLAY_SEND DISCONNECTED HOST_PIPE_IO RESTORED_STATE BIND_SERVICE;do
    if [[ "$selected" == *"P302_DENY_$category=DENY"* ]];then
      echo "P302_DIAG_$category=DENY"
      for witness in P302_WORKER_DESCRIPTOR_RECEIVED P302_WORKER_EXACT_LENGTH_READ P302_WORKER_CONTENT_MATCHED P302_WORKER_CLEAN_EOF P302_HOST_FD_SENT P302_HOST_WRITE_COMPLETE \
        P302_HOST_READER_RETAINED P302_HOST_READER_RELEASED_AFTER_WORKER;do
        if [[ "$selected" == *"$witness=PASS"* ]];then
          echo "$witness=PASS"
        fi
      done
      # P305 fixed config categories only; never raw device configuration.
      for config_class in FONT_SCALE MCC MNC LOCALE TOUCHSCREEN KEYBOARD KEYBOARD_HIDDEN NAVIGATION ORIENTATION SCREEN_LAYOUT UI_MODE SCREEN_SIZE SMALLEST_SCREEN_SIZE DENSITY LAYOUT_DIRECTION COLOR_MODE GRAMMATICAL_GENDER ASSETS_PATHS WINDOW_CONFIGURATION FONT_WEIGHT_ADJUSTMENT ZERO OTHER;do
        if [[ "$selected" == *"P305_CONFIG_CHANGE_${config_class}=OBSERVED"* ]];then
          echo "P305_CONFIG_CHANGE_${config_class}=OBSERVED"
        fi
      done
      # Only bounded fixed lifecycle categories and integer counts are emitted;
      # no raw Logcat, config values, PIDs, paths, account data, or stack traces.
      for lifecycle in \
        P302_LIFECYCLE_CREATE_FRESH P302_LIFECYCLE_CREATE_RESTORED \
        P302_LIFECYCLE_SERVICE_CONNECTED P302_LIFECYCLE_STREAM_WRITE_BEGIN \
        P302_LIFECYCLE_STREAM_WRITE_END P302_LIFECYCLE_SAVE_STATE \
        P302_LIFECYCLE_STOP P302_LIFECYCLE_CONFIG_HANDLED P302_LIFECYCLE_DESTROY_CONFIG \
        P302_LIFECYCLE_DESTROY_FINISH P302_LIFECYCLE_DESTROY_OTHER;do
        count="$(printf '%s\n' "$selected" | grep -Fc "$lifecycle=OBSERVED" || true)"
        echo "${lifecycle}_COUNT=$count"
      done
      exit 2
    fi
  done
  if [[ "$selected" == *"=DENY"* ]];then
    echo P302_DIAG_UNEXPECTED_CATEGORY=DENY;exit 2
  fi
  if [[ "$selected" == *"P302_HOST_REPLAY_DENIED=PASS"* ]];then break;fi
  sleep 1
done
for key in P302_MISSING_FD_DENIED P302_MISSING_FD_REJECTED \
  P302_WORKER_DESCRIPTOR_RECEIVED P302_HOST_FD_SENT \
  P302_HOST_WRITE_COMPLETE P302_HOST_READER_RETAINED \
  P302_WORKER_EXACT_LENGTH_READ P302_WORKER_CONTENT_MATCHED \
  P302_WORKER_CLEAN_EOF P302_HOST_FD_RECEIPT \
  P302_HOST_READER_RELEASED_AFTER_WORKER \
  P302_HOST_REPLAY_SENT P302_WORKER_REPLAY_REJECTED \
  P302_HOST_REPLAY_DENIED;do
  n="$(printf '%s\n' "$selected" | grep -Fc "$key=PASS" || true)"
  [[ "$n" == 1 ]] || { echo P302_REQUIRED_MARKER_COUNT=DENY;exit 2; }
done
printf '%s\n' "$selected" | awk '
/P302_MISSING_FD_DENIED=PASS/{a=NR}
/P302_MISSING_FD_REJECTED=PASS/{b=NR}
/P302_WORKER_DESCRIPTOR_RECEIVED=PASS/{c=NR}
/P302_WORKER_EXACT_LENGTH_READ=PASS/{d=NR}
/P302_WORKER_CONTENT_MATCHED=PASS/{e=NR}
/P302_WORKER_CLEAN_EOF=PASS/{f=NR}
/P302_HOST_FD_RECEIPT=PASS/{g=NR}
/P302_HOST_READER_RETAINED=PASS/{h=NR}
/P302_HOST_READER_RELEASED_AFTER_WORKER=PASS/{i=NR}
/P302_HOST_REPLAY_SENT=PASS/{j=NR}
/P302_WORKER_REPLAY_REJECTED=PASS/{k=NR}
/P302_HOST_REPLAY_DENIED=PASS/{l=NR}
END{if(!(a>0&&b>a&&c>b&&d>c&&e>d&&f>e&&g>f&&h>0&&h<g&&j>g&&k>0&&l>j&&i>l))exit 2}' || {
  echo P302_REQUIRED_ORDER=DENY;exit 2;
}
fresh_count="$(printf '%s\n' "$selected" | grep -Fc 'P302_LIFECYCLE_CREATE_FRESH=OBSERVED' || true)"
[[ "$fresh_count" == 1 ]] || { echo P302_DIAG_INVALID_FRESH_CREATE_COUNT=DENY;exit 2; }
config_handled_count="$(printf '%s\n' "$selected" | grep -Fc 'P302_LIFECYCLE_CONFIG_HANDLED=OBSERVED' || true)"
echo "P302_CONFIG_HANDLED_COUNT=$config_handled_count"
echo P302_ANDROID35_HOST_TO_ISOLATED_FD=PASS
echo P302_REAL_ANDROID_FRAMEWORK_UID_CHECK=PASS
echo P302_SYNTHETIC_PIPE_READ_AND_CLEAN_EOF=PASS
echo P302_SYNTHETIC_65536_BYTE_STREAM=PASS
echo P302_ONE_USE_REPLAY_REJECTED=PASS
echo P302_ORIGINAL_NODE_FD_INTEGRATION=NOT_WIRED
echo P302_ORIGINAL_P245=UNCHANGED
echo P302_P192_LOOPBACK_BIND_EACCES=STILL_BLOCKED
echo P302_USER_DEVICE_AND_DATA=NOT_TOUCHED
echo P302_V139_RELEASE=STRUCTURAL_BLOCKED
