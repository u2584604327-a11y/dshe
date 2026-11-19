#!/usr/bin/env bash
# P194: no Android, no original APK, no networking, no executable spawn.
set -euo pipefail
cd "$(dirname "$0")/../.."
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
javac --release 8 -d "$dir" \
  host_candidate/p149_prelaunch_witness/src/com/dsh/android/p149/P149OriginalBuilderWitness.java \
  host_candidate/p149_prelaunch_witness/test/com/dsh/android/p149/P149WitnessTest.java \
  host_candidate/p150_original_coroutine/src/com/dsh/android/p150/P150OriginalCoroutineObserver.java \
  host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java \
  host_candidate/p47_no_fallback/test/com/dsh/android/p47/P182TripleModeTest.java \
  host_candidate/p194_original_modes/src/com/dsh/android/p194/P194OriginalModeSeal.java \
  host_candidate/p194_original_modes/test/com/dsh/android/p194/P194OriginalModeSealTest.java
java -cp "$dir" com.dsh.android.p149.P149WitnessTest
java -cp "$dir" com.dsh.android.p47.P182TripleModeTest
java -cp "$dir" com.dsh.android.p194.P194OriginalModeSealTest
python3 host_candidate/p194_original_modes/audit_exact_sources.py
