#!/usr/bin/env bash
# P154: fail-closed bounded reattachment after original P132 adbd unroot.
# Only talks to emulator-5554. No Node/process startup or guest file mutation.
# Return: 0 verified QEMU + boot completed + shell UID=2000;
#         1 transport never became ready; 2 unsafe identity/uid/config.
p154_verify_shell_reattach(){
  local attempts="${P154_ADBD_ATTEMPTS:-10}"
  local waitsecs="${P154_ADBD_WAIT_SECONDS:-3}"
  local sleepsecs="${P154_ADBD_SLEEP_SECONDS:-1}"
  local i qemu hardware uid boot
  if [[ ! "$attempts" =~ ^[0-9]+$ || ! "$waitsecs" =~ ^[0-9]+$ ||
        ! "$sleepsecs" =~ ^[0-9]+$ ]] ||
     (( attempts<1 || attempts>20 || waitsecs<1 || waitsecs>6 || sleepsecs>2 ));then
    echo P154_ADBD_CONFIG=INVALID;return 2
  fi
  for ((i=1;i<=attempts;i++));do
    if timeout "${waitsecs}s" adb -s emulator-5554 wait-for-device >/dev/null 2>&1;then
      qemu="$(timeout 3s adb -s emulator-5554 shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r' || true)"
      hardware="$(timeout 3s adb -s emulator-5554 shell getprop ro.hardware 2>/dev/null | tr -d '\r' || true)"
      uid="$(timeout 3s adb -s emulator-5554 shell id -u 2>/dev/null | tr -d '\r' || true)"
      boot="$(timeout 3s adb -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
      if [[ "$qemu" == 1 ]];then
        case "$hardware" in ranchu|goldfish) ;; *)
          echo P154_ADBD_ORIGIN=UNSAFE_NOT_EMULATOR;return 2;;esac
        case "$uid" in
          2000)
            if [[ "$boot" == 1 ]];then
              echo P154_ADBD_POST_UNROOT=VERIFIED_EMULATOR_SHELL_UID_2000
              return 0
            fi ;;
          0|"") ;; # adbd restarting, never run Node under root
          *) echo P154_ADBD_UID=UNSAFE;return 2;;
        esac
      elif [[ -n "$qemu" ]];then
        echo P154_ADBD_ORIGIN=UNSAFE_NON_QEMU;return 2
      fi
    fi
    if ((i<attempts)) && ((sleepsecs>0));then sleep "$sleepsecs";fi
  done
  echo P154_ADBD_POST_UNROOT=BLOCKED_TRANSPORT_OR_UID_NOT_READY
  return 1
}
