#!/usr/bin/env bash
# P155 offline mocked ADB checks; never connects a real device.
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd)"
source "$base/p155_original_guest_lib_visibility.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/stage/lib" "$tmp/bin"
printf 'synthetic-z\n' > "$tmp/stage/lib/libz.so.1"
printf 'synthetic-cares\n' > "$tmp/stage/lib/libcares.so"
cat > "$tmp/bin/adb" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == emulator-5554 && "$3" == shell ]] || exit 51
command="${4:-}"
case "$command" in
  "if test -f "*)
    case "${P155_MOCK_CASE:-ok}" in
      absent) echo ABSENT ;;
      denied) echo UNREADABLE ;;
      *) echo READABLE ;;
    esac ;;
  "sha256sum "*)
    if [[ "$command" == *"libz.so.1"* ]]; then
      file="$P155_MOCK_STAGE/lib/libz.so.1"
    elif [[ "$command" == *"libcares.so"* ]]; then
      file="$P155_MOCK_STAGE/lib/libcares.so"
    else exit 52;fi
    case "${P155_MOCK_CASE:-ok}" in
      mismatch) printf '%064d  fixture\n' 0 ;;
      *) sha256sum "$file" ;;
    esac ;;
  *) exit 53 ;;
esac
MOCK
chmod +x "$tmp/bin/adb"
export PATH="$tmp/bin:$PATH" P155_MOCK_STAGE="$tmp/stage"
export P155_MOCK_CASE=ok
result="$(p155_check_guest_libs "$tmp/stage")"
grep -Fq 'P155_GUEST_LIBZ_AND_CARES_SHELL_READ=PASS_NO_LOADER_CLAIM' <<< "$result"
for scenario in absent denied mismatch;do
  export P155_MOCK_CASE="$scenario"
  set +e
  result="$(p155_check_guest_libs "$tmp/stage")"
  rc=$?
  set -e
  case "$scenario" in
    absent) [[ "$rc" == 1 && "$result" == *'ABSENT'* ]] ;;
    denied) [[ "$rc" == 1 && "$result" == *'UNREADABLE'* ]] ;;
    mismatch) [[ "$rc" == 2 && "$result" == *'SHA_MISMATCH'* ]] ;;
  esac
done
echo P155_GUEST_LIB_MOCK_PASS_AND_NEGATIVES=PASS
echo P155_ORIGINAL_NODE_EXECUTED=NO
