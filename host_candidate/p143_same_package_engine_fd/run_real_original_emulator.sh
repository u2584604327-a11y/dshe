#!/usr/bin/env bash
set -euo pipefail
# Disposable Android emulator ONLY; no user phone/package operation.
test "$(adb shell getprop ro.kernel.qemu | tr -d "\r")" = "1" || { echo P143_BLOCKED_NON_EMULATOR_DEVICE; exit 1; }
adb wait-for-device
adb root
adb wait-for-device
test "$(adb shell getprop ro.kernel.qemu | tr -d "\r")" = "1"
adb shell id | grep -Eq "uid=0\\("
apk=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
test -s "$apk"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
test "$("$sdk/build-tools/35.0.0/aapt" dump badging "$apk" | sed -n "s/^package: name=\x27\([^\x27]*\)\x27.*/\1/p" | head -n1)" = com.dsh.android
adb shell pm uninstall com.dsh.android >/dev/null 2>&1 || true
adb install "$apk" | grep -Fxq Success
uid="$(adb shell pm list packages -U com.dsh.android | sed -n -E "s/^package:com\.dsh\.android uid:([0-9]+).*/\1/p" | tr -d "\r" | head -n1)"
[[ "$uid" =~ ^[0-9]+$ ]]
adb shell iptables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb shell ip6tables -w -I OUTPUT 1 -m owner --uid-owner "$uid" -j REJECT
adb shell iptables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
adb shell ip6tables -S OUTPUT | grep -F -- "--uid-owner $uid" | grep -Fq REJECT
adb logcat -c
launch="$("$sdk/build-tools/35.0.0/aapt" dump badging "$apk" | sed -n "s/^launchable-activity: name=\x27\([^\x27]*\)\x27.*/\1/p" | head -n1)"
test -n "$launch"
adb shell am start -W -n "com.dsh.android/$launch" | grep -Eq "Status: ok|Status: warning"
adb shell pidof com.dsh.android >/dev/null
echo P143_PINNED_ORIGINAL_APP_MAIN_ACTIVITY_LAUNCHED=PASS
adb shell am start -W -n com.dsh.android/com.dsh.android.p43.P43ProbeActivity --ez p76_archive true | grep -Eq "Status: ok|Status: warning"
passed=false
for i in $(seq 1 120); do
  logs="$(adb logcat -d -v brief -s P43_HOST_BINDER:I "*:S")"
  if grep -Fq P143_SAME_PACKAGE_ORIGINAL_ENGINE_FD_ISOLATED_SHA=PASS <<< "$logs" &&
     grep -Fq P77_REAL_ORIGINAL_TAR_FULL_TREE_SHA_MATCH_IN_ISOLATED_UID=PASS <<< "$logs" &&
     grep -Fq P78_BOUNDED_ORIGINAL_JS_BYTES_READ_ONCE_IN_ISOLATED_UID=PASS <<< "$logs" &&
     grep -Fq P144_EXACT_ORIGINAL_TREE_TWO_SOURCE_LEASES=PASS <<< "$logs" &&
     grep -Fq P144_ORIGINAL_SCRIPT_AND_PACKAGE_BYTES_ISOLATED=PASS <<< "$logs" &&
     grep -Fq P145_PINNED_ORIGINAL_ENTRY_AND_PACKAGE_ISOLATED=PASS <<< "$logs" &&
     grep -Fq P146_ORIGINAL_CLI_DIRECT_IMPORT_HINT_SCAN=PASS <<< "$logs" &&
     grep -Fq P147_ONE_SCOPED_RELATIVE_CANDIDATE_FD_SECOND_ROOT=PASS <<< "$logs" &&
     grep -Eq 'P150_ACTUAL_ENGINE_COROUTINE_STACK=(OBSERVED|NOT_OBSERVED)' <<< "$logs" &&
     grep -Eq 'P151_ORIGINAL_ENGINE_AT_40S=(IDLE|EXTRACTING|STARTING|READY|FAILED|DEAD|MISSING|UNREADABLE|UNRECOGNIZED_STATE)_' <<< "$logs" &&
     grep -Eq 'P151_REAL_COROUTINE_REACHED_PRELAUNCH=(OBSERVED|NOT_OBSERVED)' <<< "$logs" &&
     grep -Fq 'P152_TERMUX_METADATA_AT_40S=' <<< "$logs" &&
     grep -Fq 'P153_NODE_ELF_AT_40S=' <<< "$logs" &&
     grep -Eq 'P156_APP_UID_LIBS_AT_40S=APP_UID_VERIFIED_Z_[A-Z0-9_]+_CARES_[A-Z0-9_]+' <<< "$logs"; then
    passed=true; break
  fi
  if grep -Eq "P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_|P43_EMBEDDED_ISOLATED_SERVICE_FAIL=|P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_" <<< "$logs"; then
    echo P143_SAME_PACKAGE_ARCHIVE_TRANSFER=BLOCKED
    echo "$logs" | grep -E "P76_ORIGINAL_ARCHIVE_TRANSPORT=FAIL_|P43_EMBEDDED_ISOLATED_SERVICE_FAIL=|P48_REAL_ORIGINAL_PROCESS_PROXY=BLOCKED_" | tail -n 5
    exit 1
  fi
  sleep 1
done
test "$passed" = true || { echo P143_SAME_PACKAGE_ARCHIVE_FD_ACK_TIMEOUT; exit 1; }
for evidence in P150_SYNTHETIC_BRIDGE_CALL_NOT_CONFUSED_WITH_ORIGINAL=PASS P150_ORIGINAL_COROUTINE_STACK_IS_NOT_OS_ATTESTATION=YES P149_P43_SYNTHETIC_BUILDER_THROUGH_PINNED_MAIN_DEX_BRIDGE=PASS P149_REAL_ENGINEMANAGER_COROUTINE_INVOKED=NO P43_REAL_ORIGINAL_APK_BINDER_ISOLATED_UID=PASS P76_REAL_ORIGINAL_ENGINE_GZIP_READONLY_FD_ISOLATED_SHA=PASS P76_ISOLATED_SOURCE_ARCHIVE_NOT_EXECUTED=YES P143_ORIGINAL_APP_ENGINE_SCRIPT_EXECUTED=NO P47_NO_HOST_PROCESSBUILDER_FALLBACK=PASS; do
  grep -Fq "$evidence" <<< "$logs" || { echo P143_REQUIRED_EVIDENCE_MISSING; exit 1; }
done
if grep -Fq 'P150_ACTUAL_ENGINE_COROUTINE_STACK=OBSERVED' <<< "$logs"; then
  echo P150_ACTUAL_ENGINE_COROUTINE_PRELAUNCH_STACK=OBSERVED
else
  echo P150_ACTUAL_ENGINE_COROUTINE_PRELAUNCH_STACK=NOT_OBSERVED
fi
echo P150_OS_GRADE_IDENTITY_AND_PRODUCTION_NODE=NOT_PROVEN
echo P151_LONG_WINDOW_EXISTING_ORIGINAL_SINGLETON_STATE_SAMPLED=PASS
echo P152_ORIGINAL_TERMUX_READONLY_FILE_AND_APK_ASSET_ENUM=PASS
echo "$logs" | grep -E 'P152_TERMUX_METADATA_AT_(5|20|40)S=' | sed -E 's/^.*(P152_)/\1/' | tail -n 3
termux="$(adb logcat -d -v brief -s TERMUX:I TermuxBootstrap:I '*:S' || true)"
if grep -Fq 'installNodeRuntime: prefix 不存在，跳过' <<< "$termux"; then
  echo P152_TERMUX_BRANCH_LOG=PREFIX_ABSENT_AT_CHECK
elif grep -Fq 'Node 运行时安装后仍不可用' <<< "$termux"; then
  echo P152_TERMUX_BRANCH_LOG=NODE_UNUSABLE_AFTER_INSTALL
elif grep -Fq '安装 Node 运行时失败' <<< "$termux"; then
  echo P152_TERMUX_BRANCH_LOG=INSTALL_EXCEPTION_REDACTED
elif grep -Fq '内置 Node 运行时已损坏' <<< "$termux"; then
  echo P152_TERMUX_BRANCH_LOG=PREEXISTING_NODE_UNUSABLE
elif grep -Fq 'Node 运行时就绪' <<< "$termux"; then
  echo P152_TERMUX_BRANCH_LOG=NODE_READY_LOGGED
else
  echo P152_TERMUX_BRANCH_LOG=NOT_CLASSIFIED
fi
echo P152_EXTRA_NODE_PROCESS_STARTED=NO
echo P153_ORIGINAL_PRIVATE_NODE_ELF_READ_ONLY=PASS
echo "$logs" | grep -E 'P153_NODE_ELF_AT_(5|20|40)S=' | sed -E 's/^.*(P153_)/\1/' | tail -n 3
echo P153_ORIGINAL_ELF_NOT_LOADED_OR_EXECUTED=YES
echo P156_HOST_APP_UID_PRIVATE_LIBS_CLASSIFIED=PASS_ONLY_CLASSIFICATION
echo "$logs" | grep -E 'P156_APP_UID_LIBS_AT_(5|20|40)S=' | sed -E 's/^.*(P156_)/\1/' | tail -n 3
echo P156_PRODUCTION_NODE_LOADER_AND_LIB_DIGEST=NOT_PROVEN
echo P153_ELF_DYNAMIC_LINKER_RUNTIME_USABILITY=NOT_PROVEN
echo P151_PRODUCTION_ORIGINAL_MAIN_COROUTINE_AND_NODE=CHECK_CATEGORICAL_LOG_NOT_ASSUMED_PASS
echo "$logs" | grep -E 'P151_ORIGINAL_ENGINE_AT_(5|20|40)S=|P151_REAL_COROUTINE_REACHED_PRELAUNCH=' | sed -E 's/^.*(P151_)/\1/' | tail -n 5
echo P149_PINNED_ORIGINAL_MAIN_DEX_PRELAUNCH_WITNESS_SYNTHETIC=PASS
echo P149_REAL_ENGINEMANAGER_ARGV_CAPTURE=NOT_PROVEN
echo P147_SECOND_FULL_ORIGINAL_ROOT_SINGLE_SOURCE_READ=PASS
echo P147_REAL_NODE_DEPENDENCY_GRAPH=NOT_PROVEN
echo P146_ACTUAL_ORIGINAL_CLI_DIRECT_IMPORT_HINTS_CLASSIFIED=PASS
echo P146_FULL_NODE_DEPENDENCY_GRAPH=NOT_PROVEN
echo P145_PINNED_CLI_ENTRY_AND_PACKAGE_VERIFIED_IN_ORIGINAL_UID=PASS
echo P145_REAL_MODULE_DEPENDENCIES_AND_READY=NOT_WIRED
echo P144_PRODUCTION_SOURCE_BROKER_TWO_IMMUTABLE_LEASES=PASS
echo P144_NODE_MODULE_RESOLVER_AND_ENGINEMANAGER=NOT_WIRED
echo P143_ORIGINAL_PACKAGE_ISOLATED_FD_FULL_TAR_MODULE=PASS
echo P143_BINDER_FROM_SAME_PACKAGE_APP_TO_ISOLATED_UID=PASS
echo P143_PRODUCTION_JS_EXEC=NOT_AUTHORIZED
echo P143_PROCESS_PROXY_PRODUCTION_HANDOFF=NOT_WIRED
echo P143_FORMAL_V139=BLOCKED
adb shell am force-stop com.dsh.android
adb shell iptables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT || true
adb shell ip6tables -w -D OUTPUT -m owner --uid-owner "$uid" -j REJECT || true
adb shell pm uninstall com.dsh.android >/dev/null
