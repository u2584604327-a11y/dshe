#!/usr/bin/env bash
# P161: fail-closed native UI focus + Binder generation consent gate.
# Takes only P102 synthetic lab tag filtered-log, not user/app data.
p102_native_focus_gate() {
  local path="$1" expected_revoke="$2" expected_pending="$3"
  local now_revoke now_pending latest_focus latest_lifecycle
  [[ -f "$path" ]] || return 1
  [[ "$expected_revoke" =~ ^[0-9]+$ && "$expected_pending" =~ ^[0-9]+$ ]] || return 1
  (( expected_pending >= 1 )) || return 1
  now_revoke="$(grep -Fc 'P102_NATIVE_BACKGROUND_REVOKE=PASS' "$path" || true)"
  now_pending="$(grep -Fc 'P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS' "$path" || true)"
  [[ "$now_revoke" == "$expected_revoke" && "$now_pending" == "$expected_pending" ]] || return 1
  latest_focus="$(grep -Eo 'P102_NATIVE_WINDOW_FOCUS=(YES|NO)' "$path" | tail -n1 || true)"
  [[ "$latest_focus" == P102_NATIVE_WINDOW_FOCUS=YES ]] || return 1
  latest_lifecycle="$(grep -Eo 'P102_(NATIVE_BACKGROUND_REVOKE|REAL_BINDER_PENDING_NATIVE_APPROVAL)=PASS' "$path" | tail -n1 || true)"
  [[ "$latest_lifecycle" == P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS ]] || return 1
  grep -Fq P102_PREAPPROVAL_REQUEST_GATE=PASS "$path" || return 1
  if grep -Eq 'P102_TRUSTED_EXECUTION_COUNT=|P102_NATIVE_UI_APPROVAL_DISPATCH=|P102_REAL_BINDER_NATIVE_TOOL_E2E=PASS|P102_REAL_SERVICE_BIND=FAIL' "$path";then
    return 1
  fi
  return 0
}
