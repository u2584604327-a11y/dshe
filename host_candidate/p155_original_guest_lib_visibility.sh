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
    observed="$(timeout 6s adb -s emulator-5554 shell "sha256sum '$guestlib/$soname'" 2>/dev/null | awk '{print $1}' || true)"
    if [[ ! "$observed" =~ ^[[:xdigit:]]{64}$ ]]; then
      echo "P155_GUEST_$soname=SHA_UNAVAILABLE"
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
