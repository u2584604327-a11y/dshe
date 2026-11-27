#!/usr/bin/env bash
# Zero-device negative regression for the production P102 E2E consent probe.
set -euo pipefail
source "$(dirname "$0")/p102_native_focus_gate.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/log" <<'LOG'
P102_NATIVE_WINDOW_FOCUS=NO
P102_NATIVE_FOREGROUND_BIND=PASS
P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS
P102_PREAPPROVAL_REQUEST_GATE=PASS
P102_NATIVE_WINDOW_FOCUS=YES
LOG
p102_native_focus_gate "$tmp/log" 0 1 || { echo P161_FOCUS_POSITIVE=FAIL;exit 1; }
reject() {
  if p102_native_focus_gate "$tmp/log" "$1" "$2";then
    echo P161_FOCUS_UNSAFE_STATE_ACCEPTED=FAIL;exit 1
  fi
}
reject 1 1
reject 0 2
echo P102_NATIVE_WINDOW_FOCUS=NO >> "$tmp/log"
reject 0 1
echo P102_NATIVE_WINDOW_FOCUS=YES >> "$tmp/log"
echo P102_NATIVE_BACKGROUND_REVOKE=PASS >> "$tmp/log"
reject 0 1
echo P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS >> "$tmp/log"
reject 0 1
echo P102_NATIVE_UI_APPROVAL_DISPATCH=NO >> "$tmp/log"
reject 1 2
rm "$tmp/log"
reject 0 1
echo P161_NATIVE_FOCUS_AND_SESSION_STABILITY_MOCK_NEGATIVES=PASS
echo P161_NO_SYNTHETIC_OR_REAL_NATIVE_TAP_EXECUTED=YES
