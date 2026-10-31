#!/usr/bin/env python3
"""P100 exact-original surface-event symbol provenance scan.
Outputs identifiers/paths/hashes/safe literals only; never source bodies.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

ROOT="node_modules/@deepseek-ai/"
TOKENS=(b"isReplacementSurfaceEvent",b"sourceEventSeqs")
MAX_MEMBER=12*1024*1024
SAFE_LITERAL=re.compile(rb"""['"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['"]""")
FN_PATTERNS=(
    re.compile(rb"function\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\("),
    re.compile(rb"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*(?:async\s*)?\("),
    re.compile(rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\([^()]{0,220}\)\s*\{"),
)
PROP=re.compile(rb"\b(event|message|entry|surface|session|this)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})")
MODULE=re.compile(rb"""['"](@deepseek-ai/[A-Za-z0-9_./-]{1,140})['"]""")

def nearest_names(prefix):
    found=[]
    for pat in FN_PATTERNS:
        for m in pat.finditer(prefix):
            name=m.group(1).decode("utf-8","replace")
            if name not in ("if","for","while","switch","catch"):
                found.append((m.start(),name))
    return [name for _,name in sorted(found)[-8:]]

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
            f=t.extractfile(item); require(f is not None,"SOURCE_MISSING")
            raw=f.read(MAX_MEMBER+1); require(len(raw)==item.size,"SHORT_SOURCE")
            present=[tok.decode() for tok in TOKENS if tok in raw]
            if not present:
                continue
            occurrences=[]
            for tok in TOKENS:
                start=0
                while True:
                    pos=raw.find(tok,start)
                    if pos<0: break
                    lo=max(0,pos-2200); hi=min(len(raw),pos+1800)
                    window=raw[lo:hi]
                    literals=[m.group(1).decode("utf-8","replace") for m in SAFE_LITERAL.finditer(window)]
                    props=[m.group(1).decode()+"."+m.group(2).decode() for m in PROP.finditer(window)]
                    modules=[m.group(1).decode("utf-8","replace") for m in MODULE.finditer(window)]
                    occurrences.append({
                        "token":tok.decode(),
                        "offset":pos,
                        "nearestFunctions":nearest_names(raw[max(0,pos-10000):pos]),
                        "nearbySafeLiterals":sorted(set(literals))[:60],
                        "nearbyPropertyRefs":sorted(set(props))[:60],
                        "nearbyDeepseekModules":sorted(set(modules))[:30],
                    })
                    start=pos+len(tok)
            parts=name.split("/")
            package="/".join(parts[:3]) if len(parts)>=3 else name
            rows.append({
                "package":package,
                "path":name,
                "sha12":sha(raw)[:12],
                "tokens":present,
                "occurrences":occurrences[:30],
            })
    print("P100_SURFACE_EVENT_SYMBOL_PROVENANCE="+json.dumps(rows,sort_keys=True))
    print("P100_SURFACE_EVENT_SOURCE_EXPORTED=NO")
    print("P100_SURFACE_EVENT_SYMBOL_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--original",required=True)
    a=p.parse_args(); inspect(pathlib.Path(a.original))
