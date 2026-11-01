#!/usr/bin/env bash
# P155: only inspect two exact v138 library copies under already-verified
# disposable emulator shell UID 2000. No execution, writes or raw stderr.
p155_check_guest_libs() {
  local stage="$1" guestlib="/data/data/com.termux/files/usr/lib"
  local soname expected status observed
  for soname in libz.so.1 libcares.so; do
    if [[ ! -f "$stage/lib/$soname" ]]; then
      echo "P155_STAGE_LIBRARY=ABSENT_PINNED_$soname"
      return 2
    fi
    expected="$(sha256sum "$stage/lib/$soname" | awk '{print $1}')"
    if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then
      echo P155_STAGE_SHA=INVALID
      return 2
    fi
    status="$(timeout 6s adb -s emulator-5554 shell "if test -f '$guestlib/$soname'; then if test -r '$guestlib/$soname'; then echo READABLE; else echo UNREADABLE; fi; else echo ABSENT; fi" 2>/dev/null | tr -d '\r' || true)"
    case "$status" in
      READABLE) ;;
      ABSENT|UNREADABLE)
        echo "P155_GUEST_$soname=$status"
        return 1 ;;
      *)
        echo "P155_GUEST_$soname=UNVERIFIED_TRANSPORT"
        return 1 ;;
    esac
    # Do not print raw guest stderr (the guest path and context are fixed).
    # Metadata readability is not proof that sha256sum can open the file.
    local raw_output raw_status rc
    if raw_output="$(timeout 6s adb -s emulator-5554 shell "sha256sum '$guestlib/$soname'" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
    if (( rc != 0 )); then
      case "$raw_output" in
        *"Permission denied"*|*"avc: denied"*) raw_status=OPEN_PERMISSION_DENIED ;;
        *"No such file or directory"*) raw_status=OPEN_PATH_NOT_VISIBLE ;;
        *"inaccessible or not found"*|*"sha256sum: not found"*) raw_status=HASH_COMMAND_NOT_AVAILABLE ;;
        *) if (( rc == 124 ));then raw_status=ADB_HASH_TIMEOUT;
           else raw_status=HASH_COMMAND_FAILED_UNCLASSIFIED;fi ;;
      esac
      echo "P155_GUEST_$soname=$raw_status"
      return 1
    fi
    observed="${raw_output%%[[:space:]]*}"
    if [[ ! "$observed" =~ ^[[:xdigit:]]{64}$ ]]; then
      echo "P155_GUEST_$soname=HASH_OUTPUT_UNVERIFIED"
      return 1
    fi
    if [[ "$expected" != "$observed" ]]; then
      echo "P155_GUEST_$soname=SHA_MISMATCH"
      return 2
    fi
    echo "P155_GUEST_$soname=READABLE_EXACT_SHA"
  done
  echo P155_GUEST_LIBZ_AND_CARES_SHELL_READ=PASS_NO_LOADER_CLAIM
  return 0
}
