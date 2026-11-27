#!/usr/bin/env bash
set -euo pipefail
test "$#" -ge 2
test "${P47_NO_HOST_FALLBACK:-0}" = 1
test "${P181_THREE_ORIGINAL_START_DENY:-0}" = 1
test "${P51_SIDE_BY_SIDE:-0}" = 0
# Build the current owner-bound main DEX independently of the historical P310
# exercise. Only read-only DEX members are sent to the shell-UID VM.
signed="$1"
DIR="$2"
apktool d -f -r --force-manifest "$signed" -o "$DIR/owned"
python3 -B host_candidate/p40_exact_trampoline.py patch "$signed" "$DIR/owned" --report "$DIR/owned-p40.json"
python3 -B host_candidate/p47_no_fallback/p47_gate.py patch "$DIR/owned"
python3 -B host_candidate/engine_runtime/original_startup_diagnostics.py "$signed" "$DIR/owned" --owner-bound
apktool b "$DIR/owned" -o "$DIR/owned-build-only.apk"
python3 - "$signed" "$DIR/owned-build-only.apk" "$DIR/owned-runtime.jar" <<'PYCODE'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as source, zipfile.ZipFile(sys.argv[2]) as staged:
    with zipfile.ZipFile(sys.argv[3], "w") as out:
        out.writestr("classes.dex", staged.read("classes.dex"))
        out.writestr("classes2.dex", source.read("classes2.dex"))
PYCODE
python3 -B host_candidate/p50_original_arm64_node/verify_config_dex.py "$signed" "$DIR/owned-runtime.jar" --owner-bound "${@:3}"
