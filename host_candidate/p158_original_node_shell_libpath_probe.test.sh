#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/p158_original_node_shell_libpath_probe.sh"
check() {
  local result
  result="$(p158_error_class "$1" "$2")"
  test "$result" = "$3" || { echo P158_CLASSIFIER_NEGATIVE=FAIL;exit 1; }
}
check "library libz.so.1 not found" 1 LIBRARY_NOT_FOUND
check "CANNOT LINK EXECUTABLE: undefined symbol x" 1 SYMBOL_RELOCATION
check "library not accessible for the namespace" 1 LINKER_NAMESPACE
check "Permission denied" 1 PERMISSION_OR_SELINUX
check "Exec format error" 1 EXEC_FORMAT_OR_NATIVE_BRIDGE
check "" 124 TIMEOUT
check "unknown cause" 1 UNCLASSIFIED
if (GITHUB_ACTIONS=false p158_shell_alt_loader_probe /nonexistent) > /dev/null 2>&1;then
  echo P158_NON_CI_EXECUTION_GATE=FAIL;exit 1
fi
echo P158_CLASSIFIER_NEGATIVES_AND_CI_REFUSAL=PASS
echo P158_SYNTHETIC_TEST_EXECUTES_ORIGINAL_NODE=NO
