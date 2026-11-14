#!/usr/bin/env python3
"""SHA-locked package metadata inventory for SessionController dependencies.
Reads package.json metadata only from exact original engine; never prints source,
credentials, user data, prompts, or file contents.
"""
import argparse, gzip, io, json, pathlib, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require

KEYWORDS=("agent","attachment","file","fs","remote","session","typert","workspace","model")
MAX_MEMBER=512_000

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True)
    args=p.parse_args()
    apk=pathlib.Path(args.original)
    require(apk.stat().st_size==SOURCE_BYTES,"APK_SIZE_DRIFT")
    require(file_hash(apk)==SOURCE_SHA,"APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as zf:
        require(zf.testzip() is None,"APK_CRC")
        engine=zf.read("assets/engine.bin")
    rows=[]
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as tf:
        for item in tf:
            name=item.name
            if not item.isfile() or not name.endswith("/package.json"):
                continue
            if "node_modules/@deepseek-ai/" not in name:
                continue
            require(0<=item.size<=MAX_MEMBER,"PACKAGE_JSON_TOO_LARGE")
            fh=tf.extractfile(item)
            require(fh is not None,"PACKAGE_JSON_MISSING")
            raw=fh.read(MAX_MEMBER+1)
            if len(raw)!=item.size:
                continue
            try:
                data=json.loads(raw)
            except Exception:
                continue
            package=str(data.get("name",""))
            if not package.startswith("@deepseek-ai/"):
                continue
            low=package.lower()
            if not any(k in low for k in KEYWORDS):
                continue
            deps=data.get("dependencies") if isinstance(data.get("dependencies"),dict) else {}
            peers=data.get("peerDependencies") if isinstance(data.get("peerDependencies"),dict) else {}
            rows.append({
                "name":package,
                "main":data.get("main"),
                "exports":sorted(data.get("exports",{}).keys())[:20] if isinstance(data.get("exports"),dict) else [],
                "deepseekDeps":sorted(k for k in deps if k.startswith("@deepseek-ai/"))[:35],
                "deepseekPeers":sorted(k for k in peers if k.startswith("@deepseek-ai/"))[:35],
            })
            if len(rows)>=120:
                break
    rows.sort(key=lambda x:x["name"])
    print("P99_SESSION_SERVICE_PACKAGE_INVENTORY="+json.dumps(rows,sort_keys=True))
    print("P99_SESSION_SERVICE_PACKAGE_METADATA_ONLY=PASS")

if __name__=="__main__":
    main()
