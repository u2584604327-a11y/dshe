#!/usr/bin/env bash
set -euo pipefail
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
BT="$SDK/build-tools/35.0.0"
PLATFORM="$SDK/platforms/android-35/android.jar"
test -f "$PLATFORM"
test -x "$BT/d8"
mkdir -p .p102tmp/emulator-classes .p102tmp/emulator-dex
javac --release 8 -cp "$PLATFORM" -d .p102tmp/emulator-classes \
  host_candidate/p71_browser_runtime/src/com/dsh/android/p71/P71ToolReplyOnce.java \
  host_candidate/p102_trusted_tool/src/com/dsh/android/p102/P102TrustedToolGate.java \
  host_candidate/p102_trusted_tool/android/com/dsh/android/p102/P102AndroidToolBinderPort.java \
  host_candidate/p102_trusted_tool/emulator/P102FixtureActivity.java \
  host_candidate/p102_trusted_tool/emulator/P102IsolatedWorker.java
jar cf .p102tmp/emulator-classes.jar -C .p102tmp/emulator-classes .
"$BT/d8" --min-api 34 --lib "$PLATFORM" \
  --output .p102tmp/emulator-dex .p102tmp/emulator-classes.jar
"$BT/aapt" package -f \
  -M host_candidate/p102_trusted_tool/emulator/AndroidManifest.xml \
  -I "$PLATFORM" -F .p102tmp/unsigned.apk
(cd .p102tmp/emulator-dex && zip -q -j ../unsigned.apk classes.dex)
"$BT/zipalign" -f 4 .p102tmp/unsigned.apk .p102tmp/aligned.apk
"$BT/zipalign" -c 4 .p102tmp/aligned.apk
"$BT/aapt" dump permissions .p102tmp/aligned.apk > .p102tmp/permissions.txt
if grep -Fq 'uses-permission:' .p102tmp/permissions.txt;then
  echo 'P102_ZERO_PERMISSIONS=FAIL';exit 1
fi
test "$(grep -c 'android:isolatedProcess="true"' \
  host_candidate/p102_trusted_tool/emulator/AndroidManifest.xml)" -eq 1
test "$(grep -c 'android:exported="false"' \
  host_candidate/p102_trusted_tool/emulator/AndroidManifest.xml)" -eq 1
PASS="$(openssl rand -hex 20)"
keytool -genkeypair -alias ephemeral -keyalg RSA -keysize 3072 \
  -validity 1 -storetype PKCS12 \
  -dname 'CN=P102 DISPOSABLE BINDER CI ONLY' \
  -keystore .p102tmp/test.p12 -storepass "$PASS" \
  -keypass "$PASS" -noprompt >/dev/null 2>&1
"$BT/apksigner" sign --ks .p102tmp/test.p12 --ks-key-alias ephemeral \
  --ks-pass "pass:$PASS" --key-pass "pass:$PASS" \
  --out .p102tmp/p102-emulator-only.apk .p102tmp/aligned.apk
"$BT/apksigner" verify .p102tmp/p102-emulator-only.apk
"$BT/aapt" dump badging .p102tmp/p102-emulator-only.apk \
  | grep -Fq "package: name='com.dsh.p102.trustedtoolprobe'"
echo 'P102_DISPOSABLE_NATIVE_BINDER_APK_BUILD=PASS' >> "$GITHUB_STEP_SUMMARY"
echo 'P102_ANDROID_PERMISSIONS=ZERO' >> "$GITHUB_STEP_SUMMARY"
echo 'P102_ORIGINAL_DSH_APK_OR_KEY=NOT_USED' >> "$GITHUB_STEP_SUMMARY"
