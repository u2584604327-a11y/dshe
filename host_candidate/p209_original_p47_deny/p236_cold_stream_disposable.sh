#!/usr/bin/env bash
# P236: fail-closed cold-start streaming method trace on disposable Android35.
# NOT original signed v138 PC evidence; never release or run on user phone.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
[[ "$P222_OFFLINE_PROFILE" == 1 && "$P226_OFFLINE_FULL_TRACE" == 1 ]]
[[ "$#" == 2 ]]
apk="$1"; uid="$2"; s=emulator-5554
[[ "$apk" == .p222tmp/P222-PROFILEABLE-OFFLINE-NOT-FOR-RELEASE.apk && -s "$apk" && "$uid" =~ ^[1-9][0-9]{4,6}$ ]] || { echo P236_INPUT=DENY;exit 2; }
[[ "$(adb -s "$s" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$s" shell id -u | tr -d '\r\n')" == 0 ]]
installed="$(adb -s "$s" shell pm list packages -U com.dsh.android | tr -d '\r' | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$installed" == "$uid" ]] || { echo P236_UID=DENY;exit 2; }
adb -s "$s" shell iptables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null
adb -s "$s" shell ip6tables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null
echo P236_OFFLINE_IPV4_IPV6_REJECT=PASS
remote=/data/local/tmp/p236-disposable-cold-stream.trace
bounded=/data/local/tmp/p236-disposable-cold-prefix.trace
if ! adb -s "$s" shell "test ! -e '$remote' && test ! -L '$remote' && test ! -e '$bounded' && test ! -L '$bounded'" >/dev/null 2>&1;then
 echo P236_REMOTE_PREEXISTS=DENY;exit 2
fi
umask 077
localdir="$(mktemp -d .p236-cold.XXXXXXXX)"
remote_owned=0; bounded_owned=0
cleanup(){
 adb -s "$s" shell am profile stop com.dsh.android >/dev/null 2>&1 || true
 adb -s "$s" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
 if [[ "$bounded_owned" == 1 ]];then adb -s "$s" shell rm -f "$bounded" >/dev/null 2>&1 || true;fi
 if [[ "$remote_owned" == 1 ]];then adb -s "$s" shell rm -f "$remote" >/dev/null 2>&1 || true;fi
 rm -rf -- "$localdir"
}
trap cleanup EXIT
# Only this verified offline clone's app data may be cleared.
adb -s "$s" shell am force-stop com.dsh.android >/dev/null
clear="$(adb -s "$s" shell pm clear com.dsh.android 2>/dev/null | tr -d '\r\n' || true)"
[[ "$clear" == Success ]] || { echo P236_TEMP_CLEAR=NOT_ATTESTED;exit 0; }
uid2="$(adb -s "$s" shell pm list packages -U com.dsh.android | tr -d '\r' | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid2" == "$uid" ]] || { echo P236_UID_DRIFT=DENY;exit 2; }
adb -s "$s" shell iptables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null
adb -s "$s" shell ip6tables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null
[[ -z "$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)" ]] || { echo P236_NOT_COLD=DENY;exit 2; }
# Android ActivityManagerShellCommand accepts --streaming during am start.
remote_owned=1
if ! launch="$(adb -s "$s" shell am start -W --start-profiler "$remote" --streaming -n com.dsh.android/com.dsh.android.MainActivity 2>/dev/null)";then
 echo P236_COLD_STREAM_START=NOT_ATTESTED;exit 0
fi
[[ "$launch" =~ Status:\ (ok|warning) ]] || { echo P236_COLD_STREAM_START=NOT_ATTESTED;exit 0; }
echo P236_COLD_STREAM_START=ACCEPTED
pid="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
[[ "$pid" =~ ^[1-9][0-9]{1,7}$ ]] || { echo P236_PID=NOT_ATTESTED;exit 0; }
sleep 3
again="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
[[ "$pid" == "$again" ]] || { echo P236_PID_STABILITY=NOT_ATTESTED;exit 0; }
echo P236_PID_STABILITY=PASS
if ! adb -s "$s" shell am profile stop com.dsh.android >/dev/null 2>&1;then
 echo P236_COLD_STREAM_STOP=NOT_ATTESTED;exit 0
fi
echo P236_COLD_STREAM_STOP=ACCEPTED
bytes="$(adb -s "$s" shell stat -c '%s' "$remote" 2>/dev/null | tr -d '\r\n' || true)"
if [[ ! "$bytes" =~ ^[1-9][0-9]{0,11}$ ]];then echo P236_REMOTE_SIZE=NOT_ATTESTED;exit 0;fi
if (( bytes < 7340032 ));then
 echo P236_REMOTE_SIZE=BELOW_7M
 echo P236_COLD_TRACE_EVENTS=NOT_ATTESTED
 exit 0
fi
echo P236_REMOTE_SIZE=AT_LEAST_7M
# Never pull full trace, even if it is below 16MiB.
bounded_owned=1
if ! adb -s "$s" shell "umask 077; dd if='$remote' of='$bounded' bs=65536 count=112 status=none" >/dev/null 2>&1;then
 echo P236_BOUNDED_COPY=NOT_ATTESTED;exit 0
fi
bsz="$(adb -s "$s" shell stat -c '%s' "$bounded" 2>/dev/null | tr -d '\r\n' || true)"
[[ "$bsz" == 7340032 ]] || { echo P236_BOUNDED_SIZE=DENY;exit 0; }
echo P236_BOUNDED_SIZE=PASS
if ! adb -s "$s" pull "$bounded" "$localdir/first.trace" >/dev/null 2>&1;then echo P236_FIRST_PULL=NOT_ATTESTED;exit 0;fi
if ! adb -s "$s" pull "$bounded" "$localdir/second.trace" >/dev/null 2>&1;then echo P236_SECOND_PULL=NOT_ATTESTED;exit 0;fi
if ! python3 -B host_candidate/p209_original_p47_deny/p233_prefix_replay.py "$localdir/first.trace" "$localdir/second.trace";then
 echo P236_EXACT_REPLAY=NOT_ATTESTED;exit 0
fi
echo P236_EXACT_REPLAY=PASS
# Strict original parser; only allowlisted event counts, no raw methods.
if python3 -B host_candidate/p209_original_p47_deny/p229_stream_v1_prefix.py "$localdir/first.trace";then
 echo P236_COLD_STREAM_PREFIX_PARSER=PASS
else
 echo P236_COLD_STREAM_PREFIX_PARSER=NOT_ATTESTED
fi
echo P236_MISSING_EVENT_IS_NOT_ABSENCE_PROOF=YES
echo P236_ORIGINAL_SIGNED_PC_AND_NODE_SUCCESS=NOT_ATTESTED
echo P236_FORMAL_V139=STRUCTURAL_BLOCKED
