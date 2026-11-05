#!/usr/bin/env bash
# P197 only tests neutral host-generation identity, not OS UID attestation.
set -euo pipefail
cd "$(dirname "$0")/../.."
d="$(mktemp -d)"
trap 'rm -rf "$d"' EXIT
javac --release 8 -d "$d" \
  host_candidate/p197_original_owner/src/com/dsh/android/p197/P197HostGeneration.java \
  host_candidate/p197_original_owner/test/com/dsh/android/p197/P197HostGenerationTest.java
java -cp "$d" com.dsh.android.p197.P197HostGenerationTest
