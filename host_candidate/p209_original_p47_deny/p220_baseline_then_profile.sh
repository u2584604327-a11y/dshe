#!/usr/bin/env bash
# Run original P209 gate in full, unchanged, THEN optionally an isolated trial.
set -uo pipefail
cd "$(dirname "$0")/../.."
temp="$(mktemp .p220-p209.XXXXXXXX)"
chmod 600 "$temp"
trap 'rm -f -- "$temp"' EXIT
bash host_candidate/p209_original_p47_deny/run_android35_deny.sh 2>&1 | tee "$temp"
baseline="${PIPESTATUS[0]}"
if [[ "$baseline" == 2 ]] &&
   grep -Fxq 'P209_GATE_OS_PID_UID_MISMATCH_OR_NOT_OBSERVED=DENY' "$temp" &&
   grep -Fxq 'P208_FRESH_TEST_PACKAGE_OUTBOUND_IPV4_IPV6_REJECT=PASS' "$temp";then
 echo P220_P209_BASELINE_FIRST_WITH_SEPARATE_FRESH_TRIAL=YES
 if ! bash host_candidate/p209_original_p47_deny/p220_profile_disposable.sh;then
  echo P220_PROFILE_TRIAL=NOT_ATTESTED
 fi
else
 echo P220_PROFILE_TRIAL=SKIPPED_UNSAFE_OR_BASELINE_PASSED
fi
# Never soften the original P209 gate result.
exit "$baseline"
