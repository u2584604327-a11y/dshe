#!/usr/bin/env bash
# P154 offline fixture: never touches actual ADB/emulator.
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
source "$base/p154_adbd_recovery.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin"
cat > "$tmp/bin/adb" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == emulator-5554 ]] || exit 44
shift 2
scenario="${P154_MOCK_SCENARIO:-recover}"
if [[ "$1" == wait-for-device ]];then
  if [[ "$scenario" == absent ]];then exit 1;fi
  n=0
  if test -f "$P154_MOCK_STATE";then n="$(cat "$P154_MOCK_STATE")";fi
  n=$((n+1))
  printf '%s\n' "$n" > "$P154_MOCK_STATE"
  if [[ "$scenario" == recover && "$n" == 1 ]];then exit 1;fi
  exit 0
fi
[[ "$1" == shell ]] || exit 44
case "$2 $3" in
 "getprop ro.kernel.qemu") if [[ "$scenario" == hostile ]];then echo 0;else echo 1;fi ;;
 "getprop ro.hardware") echo ranchu ;;
 "getprop sys.boot_completed") echo 1 ;;
 "id -u") if [[ "$scenario" == root ]];then echo 0;else echo 2000;fi ;;
 *) exit 44;;
esac
MOCK
chmod +x "$tmp/bin/adb"
export PATH="$tmp/bin:$PATH" P154_MOCK_STATE="$tmp/state"
export P154_ADBD_ATTEMPTS=3 P154_ADBD_WAIT_SECONDS=1 P154_ADBD_SLEEP_SECONDS=0
export P154_MOCK_SCENARIO=recover
first="$(p154_verify_shell_reattach)"
[[ "$first" == P154_ADBD_POST_UNROOT=VERIFIED_EMULATOR_SHELL_UID_2000 ]]
[[ "$(cat "$tmp/state")" == 2 ]]
export P154_MOCK_SCENARIO=absent
set +e
second="$(p154_verify_shell_reattach)"
rc=$?
set -e
[[ "$rc" == 1 && "$second" == P154_ADBD_POST_UNROOT=BLOCKED_TRANSPORT_OR_UID_NOT_READY ]]
export P154_MOCK_SCENARIO=hostile
set +e
third="$(p154_verify_shell_reattach)"
rc=$?
set -e
[[ "$rc" == 2 && "$third" == P154_ADBD_ORIGIN=UNSAFE_NON_QEMU ]]
export P154_MOCK_SCENARIO=root
set +e
fourth="$(p154_verify_shell_reattach)"
rc=$?
set -e
[[ "$rc" == 1 && "$fourth" == P154_ADBD_POST_UNROOT=BLOCKED_TRANSPORT_OR_UID_NOT_READY ]]
echo P154_ADBD_POST_UNROOT_MOCK_NEGATIVES=PASS
echo P154_SYNTHETIC_NODE_EXECUTION=NO
