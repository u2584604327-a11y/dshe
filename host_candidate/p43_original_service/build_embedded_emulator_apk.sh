#!/usr/bin/env bash
set -euo pipefail
# Temporary same-package integration test: original DSH v138 + P40 trampoline
# plus P43 isolated Service and exported test-only probe Activity.
# Never distribute/install over owner's DSH.
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
BT="$SDK/build-tools/35.0.0"
DIR=.p43tmp
mkdir -p "$DIR/classes" "$DIR/dex"
gh release download dsh-baseline-v135dsh-baseline-v135 \
  --repo "$GH_REPO" --pattern DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk \
  --dir "$DIR"
ORIGINAL="$DIR/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk"
expected="$(PYTHONPATH=host_candidate python -c 'from p35_original_engine_spawn_contract import EXPECTED;print(EXPECTED)')"
test "${#expected}" -eq 64
test "$(stat -c %s "$ORIGINAL")" -eq 147341486
printf '%s  %s\n' "$expected" "$ORIGINAL" | sha256sum -c -
apktool d -f -r --force-manifest "$ORIGINAL" -o "$DIR/decoded"
python host_candidate/p40_exact_trampoline.py patch "$ORIGINAL" "$DIR/decoded" \
  --report "$DIR/p40-offline.json"
python host_candidate/p43_original_service/inject_original_manifest.py inject \
  "$DIR/decoded/AndroidManifest.xml"
# Apktool 2.7 with --force-manifest and -r preserves resources.arsc byte-for-byte,
# but its rebuilt APK contains a *plain-text* Manifest! Compile ONLY that XML
# with aapt, then replace the invalid plaintext ZIP member with binary AXML.
"$BT/aapt" package -f -M "$DIR/decoded/AndroidManifest.xml" \
  -I "$SDK/platforms/android-35/android.jar" -I "$ORIGINAL" \
  --min-sdk-version 26 --target-sdk-version 28 \
  --version-code 138 --version-name 0.4.1 \
  -F "$DIR/manifest-only.apk"
python - "$DIR/manifest-only.apk" "$DIR/manifest-binary" <<'PY'
import pathlib,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
 raw=z.read('AndroidManifest.xml')
if len(raw)<128 or raw[:4]!=b'\x03\x00\x08\x00':
 raise RuntimeError("P43_MANIFEST_ONLY_AXML_NOT_BINARY")
out=pathlib.Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
(out/'AndroidManifest.xml').write_bytes(raw)
print('P43_ONLY_MANIFEST_COMPILED_TO_BINARY_AXML=PASS')
PY
apktool b "$DIR/decoded" -o "$DIR/rebuilt-unsigned.apk"
(cd "$DIR" && zip -q -d rebuilt-unsigned.apk AndroidManifest.xml)
(cd "$DIR/manifest-binary" && zip -q -0 ../rebuilt-unsigned.apk AndroidManifest.xml)
# apktool reassembles both original DEX files even though only classes.dex is
# patched. Restore the untouched secondary dex verbatim from SHA-pinned v138.
mkdir -p "$DIR/original-secondary"
unzip -p "$ORIGINAL" classes2.dex > "$DIR/original-secondary/classes2.dex"
test -s "$DIR/original-secondary/classes2.dex"
(cd "$DIR" && zip -q -d rebuilt-unsigned.apk classes2.dex)
(cd "$DIR/original-secondary" && zip -q -0 ../rebuilt-unsigned.apk classes2.dex)
python host_candidate/p40_exact_trampoline.py verify "$DIR/rebuilt-unsigned.apk"
python host_candidate/p43_original_service/inject_original_manifest.py verify \
  "$DIR/rebuilt-unsigned.apk"
# A third dex guarantees no replacement of original classes.dex/classes2.dex.
javac --release 8 -cp "$SDK/platforms/android-35/android.jar" \
  -d "$DIR/classes" \
  host_candidate/p43_original_service/android/com/dsh/android/p43/P43IsolatedWorker.java \
  host_candidate/p43_original_service/android/com/dsh/android/p43/P43ProbeActivity.java \
  host_candidate/p43_original_service/android/com/dsh/android/p43/P44VirtualDeviceProfile.java
jar cf "$DIR/p43.jar" -C "$DIR/classes" .
"$BT/d8" --min-api 26 --lib "$SDK/platforms/android-35/android.jar" \
  --output "$DIR/dex" "$DIR/p43.jar"
test -s "$DIR/dex/classes.dex"
test "$(unzip -Z1 "$DIR/rebuilt-unsigned.apk" | grep -Ec '^classes[0-9]+\.dex$' || true)" -eq 1
mv "$DIR/dex/classes.dex" "$DIR/dex/classes3.dex"
cp "$DIR/rebuilt-unsigned.apk" "$DIR/with-p43-dex.apk"
(cd "$DIR/dex" && zip -q -0 ../with-p43-dex.apk classes3.dex)
test "$(unzip -Z1 "$DIR/with-p43-dex.apk" | grep -Ec '^classes3.dex$')" -eq 1
"$BT/zipalign" -f -P 16 4 "$DIR/with-p43-dex.apk" "$DIR/aligned.apk"
"$BT/zipalign" -c -P 16 4 "$DIR/aligned.apk"
password="$(openssl rand -hex 20)"
keytool -genkeypair -alias temporary -keyalg RSA -keysize 3072 -validity 1 \
  -storetype PKCS12 -dname 'CN=P43 ORIGINAL DSH EMBEDDED WORKER EPHEMERAL ONLY' \
  -keystore "$DIR/ephemeral.p12" -storepass "$password" \
  -keypass "$password" -noprompt >/dev/null 2>&1
"$BT/apksigner" sign --ks "$DIR/ephemeral.p12" --ks-key-alias temporary \
  --ks-pass "pass:$password" --key-pass "pass:$password" \
  --out "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk" "$DIR/aligned.apk"
unset password
"$BT/apksigner" verify "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk"
python - "$ORIGINAL" "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk" <<'PY'
import sys,zipfile,hashlib
from androguard.core.dex import DEX
with zipfile.ZipFile(sys.argv[1]) as orig, zipfile.ZipFile(sys.argv[2]) as derived:
 def protected(z):
  return {n:hashlib.sha256(z.read(n)).hexdigest()
          for n in z.namelist() if n.startswith(('assets/','lib/')) and not n.endswith('/')}
 if protected(orig)!=protected(derived):raise RuntimeError("P43_ASSET_OR_NATIVE_LIB_DRIFT")
 def old_dex(z):
  return [n for n in z.namelist() if n in ('classes.dex','classes2.dex')]
 for dex_name in old_dex(orig):
  if dex_name=='classes2.dex' and orig.read(dex_name)!=derived.read(dex_name):
   raise RuntimeError("P43_ORIGINAL_CLASSES2_DEX_DRIFT")
 classes=DEX(derived.read('classes3.dex'))
 names={c.get_name() for c in classes.get_classes()}
 for expected in ('Lcom/dsh/android/p43/P43IsolatedWorker;',
                  'Lcom/dsh/android/p43/P43ProbeActivity;',
                  'Lcom/dsh/android/p43/P44VirtualDeviceProfile;'):
  if expected not in names:raise RuntimeError('P43_SERVICE_CLASS_MISSING')
print("P43_ORIGINAL_ASSETS_LIBRARIES_AND_SECONDARY_DEX=PASS_SHA")
print("P43_ORIGINAL_P40_TRAMPOLINE_AND_P43_CLASSES3=PASS_STATIC")
PY
"$BT/aapt" dump permissions "$ORIGINAL" \
  | grep -E '^uses-permission:' | sort > "$DIR/original-perms.txt" || true
"$BT/aapt" dump permissions "$DIR/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk" \
  | grep -E '^uses-permission:' | sort > "$DIR/candidate-perms.txt" || true
diff -u "$DIR/original-perms.txt" "$DIR/candidate-perms.txt"
echo 'P43_APK_ORIGINAL_COMPONENTS_AND_APPLICATION_PRESERVED=PASS_STATIC'
echo 'P43_ISOLATED_SERVICE_EMBEDDED_IN_REAL_ORIGINAL_PACKAGE=PASS_STATIC'
echo 'P43_REAL_NODE_ENGINE_ISOLATED=NO'
echo 'P43_V139_RELEASE=BLOCKED'
