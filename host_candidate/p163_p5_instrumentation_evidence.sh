#!/usr/bin/env bash
# P163: exact P5 original-host Android instrumentation verdict.
# Never inspect arbitrary app data; only the already captured bounded
# transient stdout and exit code of a disposable original-host test APK.
p163_check_p5_instrumentation() {
  local exit_code="$1" report="$2" marker code name
  if [[ ! "$exit_code" =~ ^[0-9]{1,3}$ ]] || ((exit_code>255));then
    echo P163_P5_ADB_EXIT_CODE=INVALID
    return 1
  fi
  if [[ "$exit_code" != 0 ]];then
    echo P163_P5_ADB_EXIT_CODE=NONZERO
    echo P163_P5_INSTRUMENTATION_SUCCESS=DENIED_NONZERO_ADB
    return 1
  fi
  if (( ${#report}>131072 )); then
    echo P163_P5_INSTRUMENTATION_REPORT=OVER_BUDGET
    return 1
  fi
  local -a keys=(P5_NATIVE_UI_REAL_ACTIVITY
    P120_ORIGINAL_HOST_ISOLATED_UID
    P121_ORIGINAL_ENGINE_FD_PREFIX
    P122_FULL_ENGINE_FD_SHA256
    P124_FIXED_CHILD_ISOLATED_UID
    P5_UNTRUSTED_SCHEMA_REJECTION
    INSTRUMENTATION_EXIT)
  local -a markers=(
    P5_NATIVE_UI_REAL_ACTIVITY=PASS_INSTRUMENTATION
    P120_ORIGINAL_HOST_ISOLATED_UID=PASS_REAL_ANDROID_BINDER
    P121_ORIGINAL_ENGINE_FD_PREFIX=PASS_REAL_ANDROID_UID_HASH_AND_DENY
    P122_FULL_ENGINE_FD_SHA256=PASS_FULL_57724933_AND_CORRUPTED_REJECTED_NO_EXEC
    P124_FIXED_CHILD_ISOLATED_UID=PASS_SYSTEM_ID_CHILD_MATCHES_FRAMEWORK_ISOLATED_UID_DENY_ALL
    P5_UNTRUSTED_SCHEMA_REJECTION=PASS_ANDROID_FIXTURE
    'INSTRUMENTATION_CODE: -1'
  )
  for ((code=0;code<${#markers[@]};code++)); do
    marker="${markers[code]}"
    if [[ "$report" != *"$marker"* ]];then
      echo "P163_P5_MISSING_REQUIRED_MARKER=${keys[code]}"
      return 1
    fi
  done
  # Bash substring checks avoid a pipefail SIGPIPE from printf|grep -q.
  # They do not waive the adb exit-code or any mandatory P5/FD/Binder gate.
  echo P163_P5_ADB_EXIT_CODE=ZERO
  echo P163_P5_ALL_7_ORIGINAL_GATES=PASS
  return 0
}
