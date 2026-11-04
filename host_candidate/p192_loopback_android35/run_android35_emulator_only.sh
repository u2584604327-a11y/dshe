#!/usr/bin/env bash
# P187B: emulated Android only. Strict PASS admission, per-run log boundary.
# No APK install/uninstall, no userdata clear, no phone, no CI dispatch.
set -euo pipefail
serial="${1:-emulator-5554}"
if [[ ! "$serial" =~ ^emulator-[0-9]+$ ]]; then
  echo 'P187B_STOP_NOT_EMULATOR_SERIAL'; exit 2
fi
if ! command -v adb >/dev/null 2>&1; then
  echo 'P187B_STOP_ADB_UNAVAILABLE'; exit 2
fi
qemu="$(adb -s "$serial" shell getprop ro.kernel.qemu | tr -d '\r\n')"
if [[ "$qemu" != 1 ]]; then
  echo 'P187B_STOP_NOT_ANDROID_EMULATOR'; exit 2
fi
if ! adb -s "$serial" shell pm path com.dsh.android | grep -Fq 'package:'; then
  echo 'P187B_STOP_P43_APP_MISSING'; exit 2
fi
# Non-sensitive random one-run marker, put in log before the test. Do not clear logs.
marker="P187B_START_$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
if [[ ! "$marker" =~ ^P187B_START_[0-9a-f]{24}$ ]]; then
  echo 'P187B_STOP_MARKER_INVALID'; exit 2
fi
adb -s "$serial" shell log -p i -t P187_RUN_BOUNDARY "$marker" >/dev/null
# The test APK must already be installed on a disposable emulator.
start_output="$(adb -s "$serial" shell am start -n \
  com.dsh.android/com.dsh.android.p43.P43ProbeActivity \
  --ez p187_loopback true 2>&1)"
if [[ "$start_output" == *"Error:"* || "$start_output" == *"Exception"* ]]; then
  echo 'P187B_STOP_PROBE_ACTIVITY_FAILED'; exit 2
fi
sleep "${P187B_OBSERVE_SECONDS:-7}"
log="$(adb -s "$serial" logcat -d -v brief -s P187_RUN_BOUNDARY:I P43_HOST_BINDER:I '*:S')"
# Never treat an absent PASS, an earlier run's stale PASS or repeated PASS as success.
P187B_EXPECTED_MARKER="$marker" python3 -c '
import os, re, sys
marker = os.environ["P187B_EXPECTED_MARKER"]
lines = sys.stdin.read().splitlines()
begins = [i for i, line in enumerate(lines)
          if re.search(r"\bP187_RUN_BOUNDARY(?:\([^)]*\))?:\s*" + re.escape(marker) + r"\s*$", line)]
if len(begins) != 1:
    print("P187B_STOP_RUN_BOUNDARY_MISSING_OR_REPEATED")
    sys.exit(2)
required = (
    "P187_HOST_UID_SELF_LOOPBACK",
    "P187_ISOLATED_BIND_127001",
    "P187_HOST_TO_ISOLATED_CONNECT_127001",
    "P187_ISOLATED_ACCEPT_NONCE",
)
observed = {key: [] for key in required}
rejected = []
for line in lines[begins[0]+1:]:
    m = re.search(r"\bP43_HOST_BINDER(?:\([^)]*\))?:\s*(P187_[A-Z0-9_]+)=([A-Z0-9_]+)\s*$", line)
    if not m:
        continue
    key, value = m.groups()
    if key in observed:
        observed[key].append(value)
    elif key.startswith("P187_") and (value not in ("PASS", "YES") or key == "P187_REQUEST_BINDER_SEND"):
        rejected.append(key)
for key in required:
    vals = observed[key]
    if vals != ["PASS"]:
        print("P187B_BLOCKED_" + key + "=" +
              ("MISSING" if not vals else "DUPLICATE" if len(vals) > 1 else "NOT_PASS"))
        sys.exit(2)
if rejected:
    print("P187B_BLOCKED_UNEXPECTED_FAILURE_MARKER")
    sys.exit(2)
for key in required:
    print(key + "=PASS")
print("P187B_ANDROID35_LOOPBACK_VERIFIED_IN_THIS_EMULATOR_RUN=PASS")
print("P187B_REAL_NODE_HTTP_TOKEN_READY=NOT_TESTED")
' <<< "$log"
