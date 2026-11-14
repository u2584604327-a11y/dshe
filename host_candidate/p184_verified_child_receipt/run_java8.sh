#!/usr/bin/env bash
set -euo pipefail
# Offline Java8 source tests only; no app, Node, network, or credentials.
cd "$(dirname "$0")/../.."
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
javac --release 8 -d "$tmp" \
  host_candidate/p37_remote_process/src/com/dsh/p37/P37RemoteProcess.java \
  host_candidate/p184_verified_child_receipt/src/com/dsh/android/p68/P184ChildStartReceipt.java \
  host_candidate/p75_engine_rendezvous/src/com/dsh/android/p75/P75EngineStartRendezvous.java \
  host_candidate/p75_engine_rendezvous/test/com/dsh/android/p75/P75EngineStartRendezvousTest.java \
  host_candidate/p184_verified_child_receipt/test/com/dsh/android/p68/P184ChildStartReceiptTest.java
java -cp "$tmp" com.dsh.android.p75.P75EngineStartRendezvousTest
java -cp "$tmp" com.dsh.android.p68.P184ChildStartReceiptTest
