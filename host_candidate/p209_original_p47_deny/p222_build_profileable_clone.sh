#!/usr/bin/env bash
# P222: separately signed, never released, profileable-only clone for a root
# *disposable offline emulator*. All DEX/assets/permissions remain identical.
set -euo pipefail
cd "$(dirname "$0")/../.."
source host_candidate/p159_emulator_root_reattach.sh
p159_verify_disposable_root
[[ "$P222_OFFLINE_PROFILE" == 1 ]] || { echo P222_SCOPE=DENY;exit 2; }
s=emulator-5554
[[ "$(adb -s "$s" shell getprop ro.kernel.qemu | tr -d '\r\n')" == 1 ]]
[[ "$(adb -s "$s" shell id -u | tr -d '\r\n')" == 0 ]]
d=.p222tmp
base=.p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk
signed=.p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk
source_xml=.p43tmp/decoded/AndroidManifest.xml
out=$d/P222-PROFILEABLE-OFFLINE-NOT-FOR-RELEASE.apk
[[ ! -e "$d" && -s "$base" && -s "$signed" && -s "$source_xml" ]]
[[ "$(sha256sum "$signed" | cut -d' ' -f1)" == 3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5 ]]
umask 077
mkdir -m 700 -p "$d/binary"
sdk="$ANDROID_HOME"
bt="$sdk/build-tools/35.0.0"
[[ -x "$bt/aapt" && -x "$bt/apksigner" && -x "$bt/zipalign" ]]
python3 - "$source_xml" "$d/manifest.xml" <<'PY'
from pathlib import Path
from xml.etree import ElementTree as ET
import sys
ns="{http://schemas.android.com/apk/res/android}"
source=Path(sys.argv[1]);dst=Path(sys.argv[2])
assert source.is_file() and not source.is_symlink() and source.resolve()!=dst.resolve()
root=ET.parse(source).getroot()
assert root.tag=="manifest" and root.get("package")=="com.dsh.android"
apps=root.findall("application")
assert len(apps)==1
app=apps[0]
assert not app.findall("profileable")
assert app.get(ns+"debuggable") not in ("true","1")
ET.SubElement(app,"profileable",{ns+"shell":"true"})
ET.register_namespace("android",ns[1:-1])
ET.ElementTree(root).write(dst,encoding="utf-8",xml_declaration=True)
assert dst.stat().st_size<512*1024
print("P222_MANIFEST_ONLY_PROFILEABLE_SHELL_PATCH=PASS")
PY
"$bt/aapt" package -f -M "$d/manifest.xml" \
 -I "$sdk/platforms/android-35/android.jar" -I "$signed" \
 --min-sdk-version 26 --target-sdk-version 28 \
 --version-code 138 --version-name 0.4.1 -F "$d/manifest-only.apk" >/dev/null
python3 - "$d/manifest-only.apk" "$d/binary/AndroidManifest.xml" <<'PY'
import sys,zipfile
from pathlib import Path
with zipfile.ZipFile(sys.argv[1]) as z:raw=z.read("AndroidManifest.xml")
assert len(raw)>128 and raw[:4]==b"\x03\x00\x08\x00"
Path(sys.argv[2]).write_bytes(raw)
print("P222_NEW_AXML_COMPILED=PASS")
PY
cp "$base" "$d/unsigned.apk"
(cd "$d" && zip -q -d unsigned.apk AndroidManifest.xml)
(cd "$d/binary" && zip -q -0 ../unsigned.apk AndroidManifest.xml)
"$bt/zipalign" -f -P 16 4 "$d/unsigned.apk" "$d/aligned.apk"
"$bt/zipalign" -c -P 16 4 "$d/aligned.apk"
pw="$(openssl rand -hex 20)"
keytool -genkeypair -alias diagnostic -keyalg RSA -keysize 3072 -validity 1 \
 -storetype PKCS12 -dname 'CN=P222 DISPOSABLE NO RELEASE' \
 -keystore "$d/ephemeral.p12" -storepass "$pw" -keypass "$pw" \
 -noprompt >/dev/null 2>&1
"$bt/apksigner" sign --ks "$d/ephemeral.p12" --ks-key-alias diagnostic \
 --ks-pass "pass:$pw" --key-pass "pass:$pw" --out "$out" "$d/aligned.apk"
unset pw
"$bt/apksigner" verify "$out"
python3 - "$signed" "$base" "$out" <<'PY'
import sys,zipfile,hashlib,copy
from pathlib import Path
from androguard.core.apk import APK
from p221_profile_manifest_policy import ANDROID,manifest_policy
signed,base,clone=map(Path,sys.argv[1:])
assert all(p.is_file() and not p.is_symlink() and
           32<p.stat().st_size<256*1024*1024 for p in (signed,base,clone))
assert len({p.resolve() for p in (signed,base,clone)})==3
assert hashlib.sha256(signed.read_bytes()).hexdigest()=="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
a=APK(str(base)).get_android_manifest_xml()
b=APK(str(clone)).get_android_manifest_xml()
p1,p2=manifest_policy(a),manifest_policy(b)
assert not p1["debuggable"] and not p1["declared"] and not p1["eligible"]
assert not p2["debuggable"] and p2["shell_profileable"] and p2["eligible"]
def normalized(x):
 return (x.tag,tuple(sorted(x.attrib.items())),(x.text or "").strip(),
         tuple(normalized(y) for y in x))
c=copy.deepcopy(b)
app=c.findall("application")
assert len(app)==1 and len(app[0].findall("profileable"))==1
n=app[0].find("profileable")
assert len(n.attrib)==1 and n.get(ANDROID+"shell")=="true" and not len(n)
app[0].remove(n)
assert normalized(a)==normalized(c)
with zipfile.ZipFile(base) as x,zipfile.ZipFile(clone) as y:
 assert x.testzip() is None and y.testzip() is None
 members=lambda z:{n for n in z.namelist() if not n.startswith("META-INF/")}
 assert members(x)==members(y)
 for name in sorted(members(x)-{"AndroidManifest.xml"}):
  with x.open(name) as xf,y.open(name) as yf:
   while True:
    aa,bb=xf.read(131072),yf.read(131072)
    assert aa==bb
    if not aa:break
 assert x.read("AndroidManifest.xml")!=y.read("AndroidManifest.xml")
print("P222_SIGNED_ORIGINAL_SHA_UNCHANGED=PASS")
print("P222_ONLY_MANIFEST_PROFILEABLE_DELTA=PASS")
print("P222_ALL_DEX_ASSETS_PERMISSIONS_OTHER_PAYLOADS=UNCHANGED")
print("P222_CLONE_DEBUGGABLE=NO")
print("P222_CLONE_PROFILEABLE_SHELL=YES")
print("P222_NOT_VALID_FOR_USER_OR_PRODUCTION=YES")
print("P222_DISPOSABLE_PROFILEABLE_ONLY_AUDIT=PASS")
PY
echo P222_TEMPORARY_PROFILED_APK_READY=PASS
