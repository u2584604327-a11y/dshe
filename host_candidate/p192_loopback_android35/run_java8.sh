#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
javac --release 8 -d "$tmp" \
  host_candidate/p187_loopback_capability/src/com/dsh/android/p187/P187LoopbackCapability.java \
  host_candidate/p187_loopback_capability/test/com/dsh/android/p187/P187LoopbackCapabilityTest.java
java -cp "$tmp" com.dsh.android.p187.P187LoopbackCapabilityTest
