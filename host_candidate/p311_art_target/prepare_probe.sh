#!/usr/bin/env bash
set -euo pipefail
# P311 Java-only class-loading observer. P310 built the exact temp signed APK.
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
BT="$SDK/build-tools/35.0.0"
DIR=.p311tmp
mkdir -p "$DIR/classes" "$DIR/dex"
test -s .p310tmp/P310-ART-VERIFY-EMULATOR-ONLY.apk
test -s "$SDK/platforms/android-35/android.jar"
test -x "$BT/d8"
javac --release 8 -cp "$SDK/platforms/android-35/android.jar" \
  -d "$DIR/classes" host_candidate/p311_art_target/TargetClassProbe.java
test -s "$DIR/classes/com/dsh/p311/TargetClassProbe.class"
jar cf "$DIR/probe-classes.jar" -C "$DIR/classes" .
"$BT/d8" --min-api 35 --lib "$SDK/platforms/android-35/android.jar" \
  --output "$DIR/dex" "$DIR/probe-classes.jar" > "$DIR/d8.log" 2>&1
test -s "$DIR/dex/classes.dex"
(cd "$DIR/dex" && zip -q -0 ../P311-PROBE-ANDROID35-TEST-ONLY.jar classes.dex)
test -s "$DIR/P311-PROBE-ANDROID35-TEST-ONLY.jar"
python3 - "$DIR/P311-PROBE-ANDROID35-TEST-ONLY.jar" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
 assert z.namelist()==["classes.dex"]
 assert z.read("classes.dex").startswith(bytes((100,101,120,10)))
print("P311_JAVA_ONLY_TEST_HARNESS_DEX=PASS")
PY
echo P311_PREVIOUS_P310_CANDIDATE_REUSED=YES
echo P311_NO_ORIGINAL_APP_OR_NODE_EXECUTION=YES
