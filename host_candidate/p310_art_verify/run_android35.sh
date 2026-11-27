#!/usr/bin/env bash
set -euo pipefail
# P310 install+package verify in fresh Android35 x86_64 only; NO activity/Node run.
SERIAL="$(adb devices | awk '/device$/{print $1}' | head -n1)"
[[ -n "$SERIAL" && "$SERIAL" != *":"* ]]
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
BT="$SDK/build-tools/35.0.0"
APK=.p310tmp/P310-ART-VERIFY-EMULATOR-ONLY.apk
test -s "$APK"
adb -s "$SERIAL" wait-for-device
sdk="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk | tr -d '\r')"
arch="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')"
[[ "$sdk" == 35 && "$arch" == x86_64 ]] || { echo P310_EXPECTED_REAL_ANDROID35_X86_EMULATOR=DENY;exit 2;}
adb -s "$SERIAL" root >/dev/null
adb -s "$SERIAL" wait-for-device
adb -s "$SERIAL" shell id | grep -Eq 'uid=0\('
if adb -s "$SERIAL" shell pm list packages com.dsh.android | grep -Fxq 'package:com.dsh.android';then
 echo P310_PACKAGE_ALREADY_INSTALLED=DENY;exit 2
fi
# No APK installation on user devices. Never start Activity or call original EngineManager.
done_cleanup() {
  adb -s "$SERIAL" shell am force-stop com.dsh.android >/dev/null 2>&1 || true
  if [[ -n "${APP_UID:-}" ]]; then
    adb -s "$SERIAL" shell iptables -w -D OUTPUT -m owner --uid-owner "$APP_UID" -j REJECT >/dev/null 2>&1 || true
    adb -s "$SERIAL" shell ip6tables -w -D OUTPUT -m owner --uid-owner "$APP_UID" -j REJECT >/dev/null 2>&1 || true
  fi
  adb -s "$SERIAL" shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
}
trap done_cleanup EXIT
if ! adb -s "$SERIAL" install "$APK" >.p310tmp/install-result.log 2>&1;then
 echo P310_ART_EMULATOR_APK_INSTALL=DENY;exit 2
fi
grep -Fxq Success .p310tmp/install-result.log
echo P310_REAL_ANDROID35_PACKAGE_INSTALL=PASS
APP_UID="$(adb -s "$SERIAL" shell pm list packages -U com.dsh.android | sed -n -E 's/^package:com\.dsh\.android uid:([0-9]+).*/\1/p' | tr -d '\r' | head -n1)"
[[ "$APP_UID" =~ ^[0-9]{4,8}$ ]] || { echo P310_UID=DENY;exit 2;}
adb -s "$SERIAL" shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$APP_UID" -j REJECT >/dev/null
adb -s "$SERIAL" shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$APP_UID" -j REJECT >/dev/null
adb -s "$SERIAL" shell iptables -S OUTPUT | grep -F -- "--uid-owner $APP_UID" | grep -Fq REJECT
adb -s "$SERIAL" shell ip6tables -S OUTPUT | grep -F -- "--uid-owner $APP_UID" | grep -Fq REJECT
echo P310_APP_UID_IPV4_IPV6_EGRESS=DENY
adb -s "$SERIAL" shell am force-stop com.dsh.android >/dev/null
# Android runtime's supported package-manager verify compilation filter.
# A success only proves request accepted/processing completed; NOT class-load correctness.
set +e
adb -s "$SERIAL" shell cmd package compile -f -m verify com.dsh.android >.p310tmp/art-verify-result.log 2>&1
verify_rc=$?
set -e
if [[ "$verify_rc" != 0 ]] || ! grep -Fxq 'Success' .p310tmp/art-verify-result.log;then
 echo P310_ART_VERIFY_COMMAND=DENY;exit 2
fi
echo P310_REAL_ANDROID35_PACKAGE_VERIFY_COMMAND=PASS_LIMITED
# Require app not started; 'cmd package compile' must not initialize EngineManager.
pid="$(adb -s "$SERIAL" shell pidof com.dsh.android | tr -d '\r' || true)"
if [[ -n "$pid" ]];then echo P310_FORBIDDEN_APP_PROCESS=DENY;exit 2;fi
echo P310_ORIGINAL_APP_PROCESS_STARTED=NO
echo P310_ORIGINAL_NODE_STARTED=NO
echo P310_ART_SINGLE_CLASS_LOADING_AND_VERIFIER_PROOF=NOT_ATTESTED
echo P310_ARM64_ART_VERIFIER=NOT_ATTESTED
echo P310_ORIGINAL_P245=UNMODIFIED_DENY
echo P310_P192_B3_B4=UNMODIFIED_DENY
echo P310_FORMAL_V139=STRUCTURAL_BLOCKED
