#!/usr/bin/env bash
# No Android emulator, signing, account, network egress or user data.
set -euo pipefail
cd "$(dirname "$0")/../.."
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
javac --release 8 -d "$root" \
  host_candidate/p193_host_loopback/src/com/dsh/android/p193/P193HostLoopbackFixture.java \
  host_candidate/p193_host_loopback/test/com/dsh/android/p193/P193HostLoopbackFixtureTest.java
java -cp "$root" com.dsh.android.p193.P193HostLoopbackFixtureTest
