#!/usr/bin/env bash
set -euo pipefail
# P310 only: source-pinned temporary P294 candidate; independent original P245 DENY.
# No original Java/DEX release source change and no production/owner signer.
DIR=.p310tmp
SIGNED=.p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk
BASE=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
UNSIGNED=.p245tmp/P294-UNSIGNED-DO-NOT-INSTALL.apk
FINAL="$DIR/P310-ART-VERIFY-EMULATOR-ONLY.apk"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
BT="$SDK/build-tools/35.0.0"
test -x "$BT/zipalign" && test -x "$BT/apksigner"
test -s "$BT/../../platforms/android-35/android.jar"
mkdir -p "$DIR" .p245tmp
test "$(git hash-object host_candidate/p245_build_only_probe/p245_build_only_probe.py)" = 06f62f4d8c8ee141b6b2030ee6556c9a43d9e499
test "$(git hash-object host_candidate/p47_no_fallback/android/com/dsh/android/p47/P47LaunchGate.java)" = 44cd38245dc87b9eff960b15dc520e60a2754c2c
test "$(git hash-object host_candidate/p43_original_service/build_embedded_emulator_apk.sh)" = 62ad8b62d5c0bfadf7d3b98294fd8713fb8f686f
python3 -B host_candidate/p208_original_start_coroutine/patch_ci_only.py --prepare-builder
python3 -B host_candidate/p209_original_p47_deny/patch_gate_ci_only.py --prepare
if ! bash host_candidate/p43_original_service/build_embedded_emulator_apk.sh > "$DIR/baseline-build.log" 2>&1;then
 echo P310_ORIGINAL_BASELINE_BUILD=DENY;exit 2
fi
test -s "$SIGNED" && test -s "$BASE"
printf '%s  %s\n' 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5 "$SIGNED" | sha256sum -c - >/dev/null
grep -Fxq 'P43_ORIGINAL_ASSETS_LIBRARIES_AND_SECONDARY_DEX=PASS_SHA' "$DIR/baseline-build.log"
grep -Fxq 'P47_REBUILT_ORIGINAL_PRIMARY_ENGINE_BRIDGE_NO_HOST_START=PASS' "$DIR/baseline-build.log"
grep -Fxq 'P181_ORIGINAL_V138_THREE_ENGINE_SPAWN_SITES_NO_HOST_EXEC=PASS' "$DIR/baseline-build.log"
grep -Fxq 'P182_ORIGINAL_V138_TYPED_DENY_BRIDGES_VERIFIED_IN_REBUILT_DEX=PASS' "$DIR/baseline-build.log"
echo P310_PINNED_ORIGINAL_DERIVED_BASE=PASS
# Temporary original smali is restored byte-for-byte even on failure.
trap 'python3 -B host_candidate/p279_counterfactual/p279_counterfactual.py --restore >/dev/null 2>&1 || true; python3 -B host_candidate/p245_build_only_probe/p245_build_only_probe.py --restore >/dev/null 2>&1 || true' EXIT
python3 -B host_candidate/p245_build_only_probe/p245_build_only_probe.py --patch >/dev/null
python3 -B host_candidate/p279_counterfactual/p279_counterfactual.py --apply >/dev/null
if ! apktool b .p43tmp/decoded -o "$UNSIGNED" > "$DIR/candidate-build.log" 2>&1;then
 echo P310_P294_TEMP_CANDIDATE_BUILD=DENY;exit 2
fi
python3 -B host_candidate/p279_counterfactual/p279_counterfactual.py --restore >/dev/null
python3 -B host_candidate/p245_build_only_probe/p245_build_only_probe.py --restore >/dev/null
trap - EXIT
echo P310_TEMP_ORIGINAL_SMALI_RESTORED=BYTE_EXACT
# Preserve original P43 classes3 and validated compiled manifest, not Apktool text.
python3 - "$BASE" "$UNSIGNED" <<'PY'
import sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as a,zipfile.ZipFile(sys.argv[2],"a") as b:
    assert "classes3.dex" not in b.namelist()
    b.writestr("classes3.dex",a.read("classes3.dex"),compress_type=zipfile.ZIP_STORED)
print("P310_DISPOSABLE_CLASSES3=VERBATIM")
PY
python3 -B host_candidate/p293_manifest_parity/p293_manifest_parity.py --stage > "$DIR/manifest-stage.log"
grep -Fxq 'P293_STAGE_FROM_VALIDATED_BASE=BYTE_EXACT' "$DIR/manifest-stage.log"
(cd .p245tmp && zip -q -d P294-UNSIGNED-DO-NOT-INSTALL.apk AndroidManifest.xml)
(cd .p245tmp/p293-staged-manifest && zip -q -0 ../P294-UNSIGNED-DO-NOT-INSTALL.apk AndroidManifest.xml)
python3 -B host_candidate/p293_manifest_parity/p293_manifest_parity.py --verify > "$DIR/manifest-verify.log"
grep -Fxq 'P293_FINAL_MANIFEST_MEMBER=BYTE_EXACT_BASELINE' "$DIR/manifest-verify.log"
echo P310_BINARY_MANIFEST_RESTORED=BYTE_EXACT
# Run unchanged P245 and strict P291 cloned gate on THE SAME temporary APK.
python3 -B host_candidate/p291_candidate_gate/p291_candidate_gate.py --create-copy > "$DIR/source-clone.log"
grep -Fxq 'P291_ORIGINAL_P245_SOURCE=BYTE_EXACT_UNMODIFIED' "$DIR/source-clone.log"
set +e
python3 -B host_candidate/p245_build_only_probe/p245_build_only_probe.py --verify "$UNSIGNED" > "$DIR/p245-unchanged.log" 2>&1
old_rc=$?
python3 -B .p291tmp/P291-TEMP-P245-VERIFIER-DO-NOT-RELEASE.py --verify "$UNSIGNED" > "$DIR/p291-temporary.log" 2>&1
strict_rc=$?
set -e
if [[ "$old_rc" -ne 2 ]] || ! grep -Fxq 'P245_BUILD_ONLY_DENY_CODE=P209_NODE_BOOTSTRAP_DENY_HELPER_TYPED_READ_AND_CATCH' "$DIR/p245-unchanged.log";then
 echo P310_EXPECTED_UNCHANGED_P245_DENY=FAIL_CLOSED;exit 2
fi
echo P310_ORIGINAL_P245_REMAINS_DENY=PASS
if [[ "$strict_rc" -ne 0 ]] || ! grep -Fxq 'P245_STATIC_BUILD_ONLY=PASS' "$DIR/p291-temporary.log";then
 echo P310_STRICT_CLONED_STATIC=DENY;exit 2
fi
echo P310_STRICT_CLONED_STATIC=PASS_NOT_RELEASE
# Check every protected asset and native library content against pinned P43.
python3 - "$BASE" "$UNSIGNED" <<'PY'
import hashlib,sys,zipfile
with zipfile.ZipFile(sys.argv[1]) as a,zipfile.ZipFile(sys.argv[2]) as b:
 def items(z):
  return {n:hashlib.sha256(z.read(n)).digest() for n in z.namelist()
          if n.startswith(("assets/","lib/")) and not n.endswith("/")}
 assert items(a)==items(b)
 assert b.namelist().count("classes3.dex")==1
 assert b.namelist().count("AndroidManifest.xml")==1
 assert a.read("classes3.dex")==b.read("classes3.dex")
 assert a.read("AndroidManifest.xml")==b.read("AndroidManifest.xml")
print("P310_ORIGINAL_ASSETS_NATIVE_LIBS_CLASSES3_MANIFEST=BYTE_EXACT")
PY
# New, throwaway signing identity. Never sign with original owner certificate.
"$BT/zipalign" -f -P 16 4 "$UNSIGNED" "$DIR/aligned-unsigned.apk"
"$BT/zipalign" -c -P 16 4 "$DIR/aligned-unsigned.apk" >/dev/null
secret="$(openssl rand -hex 24)"
keytool -genkeypair -alias p310 -keyalg RSA -keysize 3072 -validity 1 \
  -storetype PKCS12 -dname "CN=P310 EPHEMERAL ANDROID35 ART ONLY" \
  -keystore "$DIR/temporary-key.p12" -storepass "$secret" -keypass "$secret" -noprompt >/dev/null 2>&1
"$BT/apksigner" sign --ks "$DIR/temporary-key.p12" --ks-key-alias p310 \
  --ks-pass "pass:$secret" --key-pass "pass:$secret" --out "$FINAL" "$DIR/aligned-unsigned.apk"
unset secret
"$BT/apksigner" verify "$FINAL" >/dev/null
cert_base="$("$BT/apksigner" verify --print-certs "$SIGNED" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n1)"
cert_temp="$("$BT/apksigner" verify --print-certs "$FINAL" | sed -n 's/^Signer #1 certificate SHA-256 digest: //p' | head -n1)"
test "${#cert_base}" -eq 64 && test "${#cert_temp}" -eq 64 && test "$cert_base" != "$cert_temp"
test -s "$FINAL"
echo P310_EMULATOR_APK_EPHEMERAL_SIGNER_NOT_OWNER=PASS
echo P310_ART=NOT_YET_TESTED
echo P310_FORMAL_P245=DENY
echo P310_V139_RELEASE=STRUCTURAL_BLOCKED
