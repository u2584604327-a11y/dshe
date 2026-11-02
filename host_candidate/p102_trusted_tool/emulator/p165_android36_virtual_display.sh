#!/usr/bin/env bash
# P165: one bounded *graphical* Android36 emulator experiment in public
# GitHub CI only. Xvfb carries NO approval, touch, accounts or app data.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true ||
      "${GITHUB_REPOSITORY:-}" != u2584604327-a11y/dshe ||
      "${RUNNER_OS:-}" != Linux ]];then
  echo P165_GITHUB_CI_SCOPE=DENIED;exit 2
fi
if [[ -z "${GITHUB_ENV:-}" || -z "${RUNNER_TEMP:-}" ]];then
  echo P165_RUNNER_ENVIRONMENT=DENIED;exit 2
fi
if ! command -v Xvfb >/dev/null || ! command -v xdpyinfo >/dev/null;then
  echo P165_VIRTUAL_DISPLAY_PREREQUISITE=UNAVAILABLE;exit 2
fi
# Do not change, unlock or inspect any real device. This is only the
# disposable Android36 software window host display.
if [[ -e /tmp/.X11-unix/X96 ]];then
  echo P165_X11_DISPLAY_ALREADY_OWNED=DENIED;exit 2
fi
Xvfb :96 -screen 0 1280x900x24 -nolisten tcp -noreset \
    > "${RUNNER_TEMP}/p165-xvfb.log" 2>&1 &
pid=$!
alive=0
for i in {1..20};do
  if ! kill -0 "$pid" 2>/dev/null;then
    echo P165_XVFB_EXITED_PREMATURELY=DENIED;exit 2
  fi
  if DISPLAY=:96 xdpyinfo >/dev/null 2>&1;then
    alive=1;break
  fi
  sleep 1
done
if [[ "$alive" != 1 ]];then
  kill "$pid" >/dev/null 2>&1 || true
  echo P165_GRAPHICAL_X11_DISPLAY_UNAVAILABLE=DENIED;exit 2
fi
printf 'DISPLAY=:96\n' >> "$GITHUB_ENV"
echo P165_XVFB_GRAPHICAL_DISPLAY_ACTIVE=PASS
echo P165_ANDROID36_NO_WINDOW_FLAG=REMOVED
echo P165_NATIVE_CONSENT_WAS_NOT_INJECTED=YES
echo P165_ORIGINAL_DSH_AND_PHONE=NOT_TOUCHED
