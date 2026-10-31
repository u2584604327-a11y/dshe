#!/usr/bin/env python3
"""P100 exact-original dsh-agent-loop .includes receiver inventory.
Outputs only file paths, hashes and safe receiver identifiers; never source.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

ROOT="node_modules/@deepseek-ai/dsh-agent-loop/"
MAX_MEMBER=3_000_000
RECEIVER=re.compile(rb"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\\?\\.)[A-Za-z_$][A-Za-z0-9_$]*){0,6})(?:\\?\\.)includes\\s*\\(")

def inspect(apk:pathlib.Path):
    require(apk.stat().st_size==SOURCE_BYTES,"APK_SIZE_DRIFT")
    require(file_hash(apk)==SOURCE_SHA,"APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"APK_CRC")
        engine=z.read("assets/engine.bin")
    rows=[]
    count=0
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as t:
        for item in t:
            count+=1
            require(count<=50000,"TAR_COUNT")
            name=item.name
            if not item.isfile() or not name.startswith(ROOT):
                continue
            if not name.endswith((".js",".mjs",".cjs")):
                continue
            require(0<=item.size<=MAX_MEMBER,"SOURCE_TOO_LARGE")
            f=t.extractfile(item)
            require(f is not None,"SOURCE_MISSING")
            raw=f.read(MAX_MEMBER+1)
            require(len(raw)==item.size,"SHORT_SOURCE")
            receivers=[]
            for m in RECEIVER.finditer(raw):
                value=m.group(1).decode("utf-8","replace").replace("?.",".")
                if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.]{0,120}",value):
                    receivers.append(value)
            if receivers:
                rows.append({
                    "path":name,
                    "sha12":sha(raw)[:12],
                    "includesReceivers":sorted(set(receivers))[:80],
                    "occurrences":len(receivers),
                })
    print("P100_AGENTLOOP_INCLUDES_RECEIVER_INVENTORY="+json.dumps(rows,sort_keys=True))
    print("P100_AGENTLOOP_SOURCE_EXPORTED=NO")
    print("P100_AGENTLOOP_INCLUDES_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True)
    a=p.parse_args()
    inspect(pathlib.Path(a.original))
