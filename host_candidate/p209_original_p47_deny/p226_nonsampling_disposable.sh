#!/usr/bin/env bash
# Separate temporary NON-SAMPLING method trace, not original signed v138.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
[[ "$P222_OFFLINE_PROFILE" == 1 && "$P226_OFFLINE_FULL_TRACE" == 1 ]]
[[ "$#" == 2 ]]
apk="$1"
expected_uid="$2"
[[ "$apk" == .p222tmp/P222-PROFILEABLE-OFFLINE-NOT-FOR-RELEASE.apk &&
   -s "$apk" && "$expected_uid" =~ ^[1-9][0-9]{4,6}$ ]] || {
  echo P226_TEMP_CLONE_BOUNDARY=DENY;exit 2;
}
s=emulator-5554
[[ "$(adb -s "$s" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$s" shell id -u | tr -d '\r\n')" == 0 ]]
uid="$(adb -s "$s" shell pm list packages -U com.dsh.android | tr -d '\r' |
 sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid" == "$expected_uid" ]] || { echo P226_UID_CHANGED=DENY;exit 2; }
adb -s "$s" shell iptables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT
adb -s "$s" shell ip6tables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT
echo P226_TEMP_UID_IPV4_IPV6_REJECT=PASS
trace=/data/local/tmp/p226-temp-full-trace.trace
bounded=/data/local/tmp/p235-disposable-bounded-prefix.trace
bounded_created=0
p235_parser_pass=0
adb -s "$s" shell test ! -e "$trace" || { echo P226_TRACE_PREEXISTS=DENY;exit 2; }
umask 077
localdir="$(mktemp -d .p226-full.XXXXXXXX)"
cleanup(){
 adb -s "$s" shell am profile stop com.dsh.android >/dev/null 2>&1 || true
 if [[ "$bounded_created" == 1 ]];then
  adb -s "$s" shell rm -f "$bounded" >/dev/null 2>&1 || true
 fi
 adb -s "$s" shell rm -f "$trace" /data/local/tmp/p227-disposable-streaming-full.trace >/dev/null 2>&1 || true
 rm -rf -- "$localdir"
}
trap cleanup EXIT
# Wipe ONLY the freshly created disposable clone's own app data.
adb -s "$s" shell am force-stop com.dsh.android >/dev/null
result="$(adb -s "$s" shell pm clear com.dsh.android | tr -d '\r\n')"
[[ "$result" == Success ]] || { echo P226_CLEAR_TEMP_APP=DENY;exit 2; }
uid2="$(adb -s "$s" shell pm list packages -U com.dsh.android | tr -d '\r' |
 sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | head -n1)"
[[ "$uid2" == "$uid" ]] || { echo P226_UID_AFTER_TEMP_CLEAR=DENY;exit 2; }
adb -s "$s" shell iptables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT
adb -s "$s" shell ip6tables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT
echo P226_NO_REAL_USER_DATA_CLEARED=YES
old="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
[[ -z "$old" ]] || { echo P226_CLONE_PROCESS_NOT_COLD=DENY;exit 2; }
# Deliberately OMIT --sampling: ART method instrumentation, not sampled stacks.
if ! start="$(adb -s "$s" shell am start -W --start-profiler "$trace" \
 -n com.dsh.android/com.dsh.android.MainActivity 2>/dev/null)";then
 echo P226_NON_SAMPLED_START=NOT_ATTESTED;exit 0
fi
[[ "$start" =~ Status:\ (ok|warning) ]] || {
 echo P226_NON_SAMPLED_START=NOT_ATTESTED;exit 0;
}
echo P226_NON_SAMPLED_FRESH_CLONE_START=ACCEPTED
pid="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
[[ "$pid" =~ ^[1-9][0-9]{1,7}$ ]] || {
 echo P226_NON_SAMPLED_PID=NOT_ATTESTED;exit 0;
}
sleep 3
after="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
if [[ "$pid" != "$after" ]];then
 echo P226_MAIN_PID_CONTINUITY=NOT_ATTESTED
 exit 0
fi
echo P226_MAIN_PID_CONTINUITY=STABLE
if ! adb -s "$s" shell am profile stop com.dsh.android >/dev/null 2>&1;then
 echo P226_NON_SAMPLED_PROFILE_STOP=NOT_ATTESTED;exit 0
fi
echo P226_NON_SAMPLED_PROFILE_STOP=ACCEPTED
if ! adb -s "$s" pull "$trace" "$localdir/data.trace" >/dev/null 2>&1;then
 echo P226_TEMP_TRACE_TRANSFER=NOT_ATTESTED;exit 0
fi
if python3 -B host_candidate/p209_original_p47_deny/p226_event_audit.py "$localdir/data.trace";then
 echo P226_FULL_METHOD_TRACE_AUDIT=PASS
else
 echo P226_FULL_METHOD_TRACE_AUDIT=NOT_ATTESTED
fi
# P227: only if cold-launch non-sampling trace was EMPTY, test a bounded
# *explicit* non-sampling streaming session on the SAME already running
# offline-clone PID. This cannot attest cold startup or original Dalvik PCs.
if [[ ! -s "$localdir/data.trace" ]];then
 stream=/data/local/tmp/p227-disposable-streaming-full.trace
 if ! adb -s "$s" shell test ! -e "$stream";then
  echo P227_PREEXISTING_STREAM_TRACE=DENY
 elif [[ "$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)" != "$pid" ]];then
  echo P227_STABLE_HOST_PID=NOT_ATTESTED
 elif ! adb -s "$s" shell iptables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 ||
      ! adb -s "$s" shell ip6tables -w -C OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1;then
  echo P227_IPV4_IPV6_DENY_LOST=DENY
 elif adb -s "$s" shell am profile start --streaming "$pid" "$stream" >/dev/null 2>&1;then
  echo P227_EXPLICIT_NON_SAMPLED_STREAMING_START=ACCEPTED
  sleep 2
  current="$(adb -s "$s" shell pidof com.dsh.android | tr -d '\r\n' || true)"
  if [[ "$current" != "$pid" ]];then
   echo P227_PROCESS_CONTINUITY=DENY
   adb -s "$s" shell am profile stop "$pid" >/dev/null 2>&1 || true
  elif adb -s "$s" shell am profile stop "$pid" >/dev/null 2>&1;then
   echo P227_EXPLICIT_NON_SAMPLED_STREAMING_STOP=ACCEPTED
   # No full-pull for oversized trace. Validate remote size first,
   # then transfer at most 8 MiB for POSITIVE-ONLY prefix observation.
   remote_bytes="$(adb -s "$s" shell stat -c '%s' "$stream" 2>/dev/null | tr -d '\r\n' || true)"
   if [[ ! "$remote_bytes" =~ ^[1-9][0-9]*$ ]];then
    echo P228_REMOTE_STREAM_FILE_SIZE=NOT_ATTESTED
   elif [[ "${#remote_bytes}" -gt 12 ]];then
    echo P228_REMOTE_TRACE_UNBOUNDED=DENY
   elif (( remote_bytes > 16777216 ));then
    echo P228_REMOTE_TRACE_BAND=ABOVE_16M_CAP
    # P235: do not stream binary prefix through adb exec-out.
    # Create a private EXACT 7MiB bounded remote snapshot of the already
    # stopped immutable trace, then use ADB's file-transfer protocol twice.
    # Never pull the >16MiB full stream, accept bytes beyond 7MiB, or log
    # raw data, hashes, paths, method IDs or user content.
    if ! adb -s "$s" shell "test ! -e '$bounded' && test ! -L '$bounded'" >/dev/null 2>&1;then
     echo P235_REMOTE_PREFIX_PREEXISTS=DENY
    else
     # Mark ownership before dd so any partially created file is cleaned.
     bounded_created=1
     if ! adb -s "$s" shell "umask 077; dd if='$stream' of='$bounded' bs=65536 count=112 status=none" >/dev/null 2>&1;then
      echo P235_REMOTE_PREFIX_CREATE=NOT_ATTESTED
     else
      bsz="$(adb -s "$s" shell stat -c '%s' "$bounded" 2>/dev/null | tr -d '\r\n' || true)"
      if [[ "$bsz" != 7340032 ]];then
       echo P235_REMOTE_PREFIX_EXACT_SIZE=DENY
      else
       echo P235_REMOTE_PREFIX_EXACT_SIZE=PASS
       if ! adb -s "$s" pull "$bounded" "$localdir/bounded-prefix.trace" >/dev/null 2>&1;then
        echo P235_FIRST_PULL=NOT_ATTESTED
       elif ! adb -s "$s" pull "$bounded" "$localdir/bounded-prefix-replay.trace" >/dev/null 2>&1;then
        echo P235_SECOND_PULL=NOT_ATTESTED
       elif python3 -B host_candidate/p209_original_p47_deny/p233_prefix_replay.py \
        "$localdir/bounded-prefix.trace" "$localdir/bounded-prefix-replay.trace";then
        echo P235_BOUNDED_TRANSFER=PASS
        if python3 -B host_candidate/p209_original_p47_deny/p229_stream_v1_prefix.py "$localdir/bounded-prefix.trace";then
         echo P230_STREAMING_PREFIX_AUDIT=PASS
         p235_parser_pass=1
        else
         echo P230_STREAMING_PREFIX_AUDIT=NOT_ATTESTED
        fi
       else
        echo P235_BOUNDED_TRANSFER=NOT_ATTESTED
        echo P230_STREAMING_PREFIX_AUDIT=NOT_ATTESTED
       fi
      fi
     fi
    fi
   elif (( remote_bytes <= 16777216 ));then
    echo P228_REMOTE_TRACE_BAND=WITHIN_16M_CAP
    if adb -s "$s" pull "$stream" "$localdir/stream.trace" >/dev/null 2>&1;then
     if python3 -B host_candidate/p209_original_p47_deny/p226_event_audit.py "$localdir/stream.trace";then
      echo P227_STRICT_NON_SAMPLED_STREAMING_AUDIT=PASS
     else
      echo P227_STRICT_NON_SAMPLED_STREAMING_AUDIT=NOT_ATTESTED
     fi
    else
     echo P227_STREAM_TRACE_TRANSFER=NOT_ATTESTED
    fi
   fi
  else
   echo P227_EXPLICIT_NON_SAMPLED_STREAMING_STOP=NOT_ATTESTED
  fi
 else
  echo P227_EXPLICIT_NON_SAMPLED_STREAMING_START=NOT_ATTESTED
 fi
else
 echo P227_STREAMING_CONTROL=SKIPPED_NONEMPTY_COLD_TRACE
fi
echo P227_EXPLICIT_SESSION_NOT_COLD_STARTUP_WITNESS=YES
echo P226_NOT_ORIGINAL_V138_PROCESS_WITNESS=YES
# P236 is a NEW disposable cold-start test, only after strict P235 PASS.
if [[ "$p235_parser_pass" == 1 ]];then
 if bash host_candidate/p209_original_p47_deny/p236_cold_stream_disposable.sh "$apk" "$uid";then
  echo P236_DISPOSABLE_COLD_EXPERIMENT=EXECUTED
 else
  echo P236_DISPOSABLE_COLD_EXPERIMENT=NOT_ATTESTED
 fi
else
 echo P236_DISPOSABLE_COLD_EXPERIMENT=SKIPPED_P235_NOT_PROVEN
fi
