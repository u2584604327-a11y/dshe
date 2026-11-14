#!/usr/bin/env bash
# P137: emit exactly one response to sdkmanager --install of a single fixed system image.
# No automatic license acceptance on PR, push, schedule or default dispatch.
set -euo pipefail
if test "$#" -ne 1 || test "$1" != choice; then echo P137_USAGE=REFUSED >&2; exit 2; fi
if test "${GITHUB_EVENT_NAME:-}" = workflow_dispatch &&
   test "${P136_LICENSE_ACKNOWLEDGEMENT:-}" = "I_ACCEPT_GOOGLE_ANDROID_SDK_LICENSE_FOR_ARM64_IMAGE"; then
  printf 'y\n'
else
  printf 'n\n'
fi
