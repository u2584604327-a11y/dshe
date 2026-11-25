#!/usr/bin/env bash
set -euo pipefail
# Disposable Android 35 x86_64. App never launched. Android shell UID only.
SERIAL="$(adb devices | awk '/device$/{print $1}' | head -n 1)"
[[ -n "$SERIAL" && "$SERIAL" != *":"* ]]
APK=.p310tmp/P310-ART-VERIFY-EMULATOR-ONLY.apk
PROBE=.p311tmp/P311-PROBE-ANDROID35-TEST-ONLY.jar
test -s "$APK" && test -s "$PROBE"
adb -s "$SERIAL" wait-for-device
sdk="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
arch="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')"
[[ "$sdk" == 35 && "$arch" == x86_64 ]] || { echo P311_REAL_ANDROID35_X86_SCOPE=DENY;exit 2;}
adb -s "$SERIAL" root >/dev/null
adb -s "$SERIAL" wait-for-device
adb -s "$SERIAL" shell id | grep -Eq 'uid=0\('
if adb -s "$SERIAL" shell pm list packages com.dsh.android | grep -Fxq 'package:com.dsh.android';then
 echo P311_PREEXISTING_PACKAGE=DENY;exit 2
fi
APP_UID=""
PROBE_PATH=/data/local/tmp/p311-one-session-probe.jar
cleanup() {
  adb -s "$SERIAL" root >/dev/null 2>&1 || true
  adb -s "$SERIAL" wait-for-device >/dev/null 2>&1 || true
  adb -s "$SERIAL" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
  for uid in "${APP_UID:-}" 2000;do
    if [[ "$uid" =~ ^[0-9]{1,8}$ ]];then
      adb -s "$SERIAL" shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
      adb -s "$SERIAL" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT >/dev/null 2>&1 || true
    fi
  done
  adb -s "$SERIAL" shell rm -f "$PROBE_PATH" >/dev/null 2>&1 || true
  adb -s "$SERIAL" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
}
trap cleanup EXIT
if ! adb -s "$SERIAL" install "$APK" >.p311tmp/install.log 2>&1;then
 echo P311_DISPOSABLE_APK_INSTALL=DENY;exit 2
fi
grep -Fxq Success .p311tmp/install.log
APP_UID="$(adb -s "$SERIAL" shell pm list packages -U com.dsh.android | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | tr -d '\r' | head -n1)"
[[ "$APP_UID" =~ ^[0-9]{4,8}$ ]] || { echo P311_APP_UID=DENY;exit 2;}
# Lock down BOTH guest app UID and shell UID BEFORE test classpath execution.
for uid in "$APP_UID" 2000;do
  adb -s "$SERIAL" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT >/dev/null
  adb -s "$SERIAL" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT >/dev/null
  adb -s "$SERIAL" shell iptables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
  adb -s "$SERIAL" shell ip6tables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
done
echo P311_APP_AND_SHELL_UID_IPV4_IPV6=DENY
adb -s "$SERIAL" shell am force-stop com.dsh.android >/dev/null
adb -s "$SERIAL" push "$PROBE" "$PROBE_PATH" >.p311tmp/push.log 2>&1
adb -s "$SERIAL" shell chmod 444 "$PROBE_PATH"
# Never unroot adbd with an OUTPUT reject on shell UID 2000: adb itself
# can lose guest transport. Keep root adbd solely for transport/firewall,
# execute only the two test dalvikvm CHILDREN as non-root UID 2000 using su.
# If the isolated emulator lacks su-to-shell, fail closed; do not remove
# shell firewall or silently run target class loading under root.
adb -s "$SERIAL" shell command -v su >/dev/null
if ! adb -s "$SERIAL" shell su 2000 id -u 2>/dev/null | tr -d '\r' | grep -Fxq 2000;then
 echo P311_SHELL_CHILD_IDENTITY=DENY;exit 2
fi
echo P311_SHELL_CHILD_UID2000_ROOT_ADBD_SEPARATED=PASS
adb -s "$SERIAL" shell command -v dalvikvm >/dev/null
rawpath="$(adb -s "$SERIAL" shell pm path com.dsh.android | tr -d '\r' | sed -n 's/^package://p' | grep -F '/base.apk' | head -n1)"
[[ "$rawpath" =~ ^/data/app/[A-Za-z0-9._+~=/\-]+/base\.apk$ ]] || {
 echo P311_CANDIDATE_APK_PATH=DENY;exit 2;
}
# Keep the original class-load controls separate from the two executions.
set +e
adb -s "$SERIAL" shell su 2000 dalvikvm -Xverify:all -cp "$PROBE_PATH" \
  com.dsh.p311.TargetClassProbe missing "$rawpath" > .p311tmp/negative.log 2>&1
neg=$?
adb -s "$SERIAL" shell su 2000 dalvikvm -Xverify:all -cp "$PROBE_PATH" \
  com.dsh.p311.TargetClassProbe target "$rawpath" > .p311tmp/target.log 2>&1
pos=$?
set -e
if [[ "$neg" -ne 0 ]] || ! grep -Fxq 'P311_NEGATIVE_MISSING_CLASS=PASS' .p311tmp/negative.log;then
 echo P311_NEGATIVE_CLASSLOADER_CONTROL=DENY;exit 2
fi
echo P311_NEGATIVE_CLASSLOADER_CONTROL=PASS
if [[ "$pos" -ne 0 ]] ||
   ! grep -Fxq 'P311_ANDROID35_TARGET_CLASS_LOADER=PASS_NARROW' .p311tmp/target.log ||
   ! grep -Fxq 'P311_TARGET_INVOKESUSPEND_SIGNATURE=PASS_NARROW' .p311tmp/target.log ||
   ! grep -Fxq 'P311_TARGET_CLASS_INITIALIZED=NO_BY_CLASS_FORNAME_FALSE' .p311tmp/target.log ||
   ! grep -Fxq 'P311_TARGET_METHOD_INVOKED=NO' .p311tmp/target.log;then
 echo P311_ART_TARGET_CLASS_LINK=DENY;exit 2
fi
echo P311_REAL_ANDROID35_TARGET_CLASS_LINK=PASS_NARROW
echo P311_REAL_ANDROID35_INVOKESUSPEND_REFLECTION=PASS_NARROW

exercise_entry() {
  local mode="$1" status="$2" expected_helper_count="$3" pid count
  local report=".p311tmp/$mode.log"
  if ! adb -s "$SERIAL" shell su 2000 dalvikvm -Xverify:all -cp "$PROBE_PATH" \
      com.dsh.p311.TargetClassProbe "$mode" "$rawpath" > "$report" 2>&1;then
    echo "P311_INVOKESUSPEND_${mode}_EXECUTION=DENY";exit 2
  fi
  grep -Fxq "$status" "$report"
  pid="$(sed -n -E 's/^P311_PROBE_PID=([0-9]+)$/\1/p' "$report")"
  [[ "$pid" =~ ^[0-9]+$ ]]
  adb -s "$SERIAL" logcat -d --pid="$pid" -v brief P208_ORIGINAL_ENTRY:I DSH:I '*:S' > ".p311tmp/$mode-device.log"
  grep -Fq 'P208_ORIGINAL_START2_COROUTINE_UID=2000' ".p311tmp/$mode-device.log"
  count="$(grep -Ec '^I/DSH[[:space:]]*\([[:space:]0-9]+\): false$' ".p311tmp/$mode-device.log" || true)"
  [[ "$count" -eq "$expected_helper_count" ]]
  echo "$status"
}
exercise_entry failure P311_INVOKESUSPEND_RESUME_FAILURE_RETHROWN=PASS 0
exercise_entry post-return P311_INVOKESUSPEND_POST_HELPER_OWNER_GUARD=PASS 1
echo P311_REAL_ANDROID35_P245_HELPER_REACHED_ONLY_AFTER_NORMAL_RETURN=PASS
pid="$(adb -s "$SERIAL" shell pidof com.dsh.android | tr -d '\r' || true)"
[[ -z "$pid" ]] || { echo P311_ORIGINAL_APP_PROCESS=DENY;exit 2;}
echo P311_ORIGINAL_APP_PROCESS_STARTED=NO
echo P311_TARGET_INVOKESUSPEND_ENTRY_EXECUTED=SHELL_UID_NULL_OWNER
echo P311_ORIGINAL_NODE_EXECUTED=NO
echo P311_ARM64_AND_PRODUCTION_ENGINE=NOT_ATTESTED
echo P311_ART_FULL_RUNTIME_AND_OWNER_BRIDGE=NOT_ATTESTED
echo P311_ORIGINAL_P245_P192_B3_B4=UNMODIFIED_DENY
echo P311_V139_RELEASE=STRUCTURAL_BLOCKED
