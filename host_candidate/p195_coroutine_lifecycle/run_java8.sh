#!/usr/bin/env bash
# P195 pure Java8 source fixture; no Android APK, ProcessBuilder.start, network.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
javac --release 8 -d "$tmp" \
  host_candidate/p149_prelaunch_witness/src/com/dsh/android/p149/P149OriginalBuilderWitness.java \
  host_candidate/p194_original_modes/src/com/dsh/android/p194/P194OriginalModeSeal.java \
  host_candidate/p37_remote_process/src/com/dsh/p37/P37RemoteProcess.java \
  host_candidate/p195_coroutine_lifecycle/src/com/dsh/android/p195/P195OriginalCoroutineLifecycle.java \
  host_candidate/p195_coroutine_lifecycle/test/com/dsh/android/p195/P195OriginalCoroutineLifecycleTest.java
java -cp "$tmp" com.dsh.android.p195.P195OriginalCoroutineLifecycleTest
