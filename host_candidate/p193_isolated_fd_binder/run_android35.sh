#!/usr/bin/env bash
# P193: fresh Android 35 x86_64 QEMU only, synthetic no-permission app.
set -euo pipefail
cd "$(dirname "$0")/../.."
serial=emulator-5554
pkg=com.dsh.p193probe
apk=host_candidate/p193_isolated_fd_binder/probe/.p193-disposable.apk
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
[[ -s "$apk" && -n "$ANDROID_HOME" ]]
[[ "$(adb -s "$serial" shell pm list packages "$pkg" | tr -d '\r')" != *"package:$pkg"* ]]
badging="$("$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "$apk")"
[[ "$badging" == *"package: name='com.dsh.p193probe'"* &&
   "$badging" != *"uses-permission:"* ]]
adb -s "$serial" install "$apk" >/dev/null
installed=YES
package_uid="$(adb -s "$serial" shell pm list packages -U "$pkg" |
  tr -d '\r' | sed -nE 's/^package:com\.dsh\.p193probe uid:([0-9]+)$/\1/p')"
[[ "$package_uid" =~ ^[0-9]+$ && "$package_uid" -gt 10000 ]]
marker="P193_RUN_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$marker" =~ ^P193_RUN_[0-9a-f]{24}$ ]]
adb -s "$serial" shell log -p i -t P193_BOUNDARY "$marker" >/dev/null
adb -s "$serial" shell am start -W -n "$pkg/.ProbeActivity" >/dev/null
selected=''
for _ in $(seq 1 35);do
  raw="$(adb -s "$serial" logcat -d -v brief -s P193_BOUNDARY:I P193_HOST:I P193_WORKER:I '*:S')"
  selected="$(printf '%s\n' "$raw" | awk -v m="$marker" '
    index($0,m){n++;live=1;next}
    live{print}
    END{if(n!=1)print "P193_BOUNDARY_INVALID"}
  ')"
  if [[ "$selected" == *P193_BOUNDARY_INVALID* ]];then
    echo P193_DIAG_UNIQUE_LOG_BOUNDARY=DENY;exit 2
  fi
  # Only fixed security categories; never UID, session, trace, or FD bytes.
  for reason in P193_DENY_BAD_SENDER P193_DENY_BAD_PARCEL P193_DENY_REPLY_TARGET_GONE P193_DENY_REPLY_IDENTITY P193_DENY_REPLY_PARCEL P193_DENY_RETURN_FRAME P193_DENY_RETURN_READ P193_DENY_REPLY_PHASE P193_DENY_INITIAL_SEND P193_DENY_SERVICE_DISCONNECTED P193_DENY_FD_SEND P193_DENY_BIND_SERVICE P193_DENY_HOST;do
    if [[ "$selected" == *"$reason=DENY"* ]];then
      echo "P193_DIAG_"$reason"=DENY";exit 2
    fi
  done
  if [[ "$selected" == *"=DENY"* ]];then
    echo P193_DIAG_OTHER_CATEGORY=DENY;exit 2
  fi
  if [[ "$selected" == *"P193_ANDROID35_HOST_ISOLATED_BINDER_FD=PASS"* ]];then break;fi
  sleep 1
done
for key in P193_MISSING_FD_REJECTED P193_WORKER_ISOLATED_FD_READ P193_ANDROID35_HOST_ISOLATED_BINDER_FD;do
  total="$(printf '%s\n' "$selected" | grep -Fc "$key=PASS" || true)"
  [[ "$total" == 1 ]] || { echo P193_REQUIRED_MARKER_COUNT=DENY;exit 2; }
done
printf '%s\n' "$selected" | awk '
/P193_MISSING_FD_REJECTED=PASS/{a=NR}
/P193_WORKER_ISOLATED_FD_READ=PASS/{b=NR}
/P193_ANDROID35_HOST_ISOLATED_BINDER_FD=PASS/{c=NR}
END {if(!(a>0 && b>a && c>b))exit 2}' || {
  echo P193_EVENT_ORDER=DENY;exit 2;
}
echo P193_NEGATIVE_MISSING_FD=PASS
echo P193_REAL_ANDROID35_BINDER_ISOLATED_UID=PASS
echo P193_REAL_ANDROID35_RELIABLE_PIPE=PASS
echo P193_ISOLATED_TCP_BIND_REQUIRED=NO
echo P193_ORIGINAL_NODE_FD_INTEGRATION=NOT_WIRED
echo P193_BROWSER_PROFILE_ROUTING=NOT_WIRED
echo P193_USER_PHONE_DATA_TOUCHED=NO
echo P193_AVF_PROTECTED_VM=NOT_ATTESTED
echo P193_V139_RELEASE=STRUCTURAL_BLOCKED
