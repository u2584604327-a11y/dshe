#!/usr/bin/env python3
"""Read-only public v91 bundled tool-assets vs exact signed modified v138.

Checks resource identity, NOT behavioral or executable compatibility.
No API keys, user data, raw APK entries, or copied third-party sources exported.
"""
import argparse
import io
import hashlib
import pathlib
import zipfile

EXPECTED_APK="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
EXPECTED_SIZE=147341486
PATHS=(
    "assets/browser-tool.zip",
    "assets/browser-pane.zip",
    "assets/logs-tool.zip",
    "assets/dsh-fetch-guard.mjs",
)
MAX_RESOURCE=8*1024*1024
PLUGIN_PACKAGES={
    "browser-tool.zip":("dsh-android-browser",("package.json","lib/index.js")),
    "browser-pane.zip":("dsh-android-browser-pane",
                        ("package.json","lib/index.js","lib/client.js")),
    "logs-tool.zip":("dsh-android-logs",("package.json","lib/index.js")),
}
def sha(b):return hashlib.sha256(b).hexdigest()
def audit(apk,public_dir,plugin_dir):
    assert apk.is_file() and apk.stat().st_size==EXPECTED_SIZE, "P105_APK_SIZE"
    h=hashlib.sha256()
    with apk.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    assert h.hexdigest()==EXPECTED_APK,"P105_APK_SHA256"
    with zipfile.ZipFile(apk) as z:
        names=z.namelist()
        assert len(names)==len(set(names)),"P105_DUPLICATE_APK_ENTRIES"
        for name in PATHS:
            assert name in names,"P105_APK_ASSET_MISSING"
            entry=z.getinfo(name)
            assert 0<entry.file_size<=MAX_RESOURCE,"P105_APK_ASSET_TOO_LARGE"
            body=z.read(name)
            disk=public_dir/name.split("/")[-1]
            if not disk.is_file():
                status="PUBLIC_SOURCE_ASSET_ABSENT"
            else:
                assert 0<disk.stat().st_size<=MAX_RESOURCE,"P105_PUBLIC_ASSET_LIMIT"
                status="IDENTICAL" if sha(body)==sha(disk.read_bytes()) else "DIFFERENT"
            print("P105_"+name.split("/")[-1].replace(".","_").upper()+"="+status)
            base=name.split("/")[-1]
            if base in PLUGIN_PACKAGES:
                pkg,paths=PLUGIN_PACKAGES[base]
                with zipfile.ZipFile(io.BytesIO(body),"r") as inner:
                    infos=inner.infolist()
                    assert len(infos)==len({i.filename for i in infos}),"P105_NESTED_DUPLICATES"
                    assert len(infos)<=100 and sum(i.file_size for i in infos)<=20*1024*1024, "P105_NESTED_SIZE"
                    members=set(inner.namelist())
                    for relative in paths:
                        upstream=plugin_dir/pkg/relative
                        label="P105_"+base.replace(".","_").replace("-","_").upper()+(
                            "_"+relative.replace("/","_").replace(".","_").upper())
                        if not upstream.is_file():
                            status="PUBLIC_MEMBER_ABSENT"
                        elif relative not in members:
                            status="V138_ARCHIVE_MEMBER_ABSENT"
                        else:
                            member=inner.getinfo(relative)
                            assert member.file_size<=MAX_RESOURCE,"P105_MEMBER_SIZE"
                            status="IDENTICAL" if sha(inner.read(relative))==sha(upstream.read_bytes()) else "DIFFERENT"
                        print(label+"="+status)
    print("P105_PUBLIC_UPSTREAM_SOURCE_VERSIONCODE=91")
    print("P105_MODIFIED_APK_VERSIONCODE=138")
    print("P105_ASSET_HASH_MATCH_IMPLIES_BEHAVIOR_MATCH=NO")
    print("P105_PUBLIC_SOURCE_BINARY_EQUIVALENCE=NOT_PROVEN")
    print("P105_ORIGINAL_AGENTLOOP_BINDER_PRODUCTION=NOT_WIRED")
    print("P105_V138_APK_OR_USER_DATA_MODIFIED=NO")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--apk",required=True,type=pathlib.Path)
    p.add_argument("--public-assets",required=True,type=pathlib.Path)
    p.add_argument("--public-plugins",required=True,type=pathlib.Path)
    a=p.parse_args()
    audit(a.apk,a.public_assets,a.public_plugins)
