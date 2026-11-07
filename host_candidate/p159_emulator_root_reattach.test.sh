#!/usr/bin/env bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
source "$base/p159_emulator_root_reattach.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/adb" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" = -s && "$2" = emulator-5554 ]] || exit 52
shift 2
scenario="${P159_SCENARIO:-transient}"
if [[ "$1" = wait-for-device ]];then
  if [[ "$scenario" = offline ]];then exit 1;fi
  exit 0
fi
if [[ "$1" = root ]];then
  num=0
  if [[ -s "$P159_STATE" ]];then num="$(cat "$P159_STATE")";fi
  printf '%s\n' "$((num+1))" > "$P159_STATE"
  if [[ "$scenario" = transient && "$num" = 0 ]];then exit 1;fi
  exit 0
fi
[[ "$1" = shell ]] || exit 52
case "$2 $3" in
  "getprop ro.kernel.qemu") [[ "$scenario" = hostile ]] && echo 0 || echo 1 ;;
  "getprop ro.hardware") echo ranchu ;;
  "getprop sys.boot_completed") echo 1 ;;
  "id -u")
    if [[ "$scenario" = wrong_uid ]];then echo 70000
    elif [[ "$scenario" = stuck_shell ]];then echo 2000
    elif [[ "$scenario" = transient ]];then
      n=0;if [[ -s "$P159_STATE" ]];then n="$(cat "$P159_STATE")";fi
      [[ "$n" -ge 2 ]] && echo 0 || echo 2000
    else echo 0;fi ;;
  *) exit 52 ;;
esac
MOCK
chmod +x "$tmp/bin/adb"
export PATH="$tmp/bin:$PATH" P159_STATE="$tmp/calls" P159_WAIT_SECONDS=1 P159_MAX_ATTEMPTS=4 P159_SLEEP_SECONDS=0
export P159_SCENARIO=transient
result="$(p159_verify_disposable_root)"
[[ "$result" = P159_EMULATOR_ROOT=VERIFIED_QEMU_UID_0 ]]
[[ "$(cat "$tmp/calls")" = 2 ]]
export P159_SCENARIO=offline
set +e
result="$(p159_verify_disposable_root)"
status=$?
set -e
[[ "$status" = 1 && "$result" = P159_EMULATOR_ROOT=BLOCKED_BOUNDED_ADBD_REATTACH ]]
export P159_SCENARIO=hostile
set +e
result="$(p159_verify_disposable_root)"
status=$?
set -e
[[ "$status" = 2 && "$result" = P159_ORIGIN=DENIED_NON_QEMU ]]
export P159_SCENARIO=wrong_uid
set +e
result="$(p159_verify_disposable_root)"
status=$?
set -e
[[ "$status" = 2 && "$result" = P159_UID=DENIED_UNKNOWN ]]
export P159_SCENARIO=stuck_shell
set +e
result="$(p159_verify_disposable_root)"
status=$?
set -e
[[ "$status" = 1 && "$result" = P159_EMULATOR_ROOT=BLOCKED_BOUNDED_ADBD_REATTACH ]]
export P159_MAX_ATTEMPTS=999
set +e
result="$(p159_verify_disposable_root)"
status=$?
set -e
[[ "$status" = 2 && "$result" = P159_CONFIG=INVALID ]]
echo P159_ADBD_EMULATOR_ROOT_MOCK_POSITIVE_AND_NEGATIVES=PASS
echo P159_MOCK_DEVICE_OR_CHILD_EXECUTION=NO
