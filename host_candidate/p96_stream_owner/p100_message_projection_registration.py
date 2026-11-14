#!/usr/bin/env python3
"""P100 exact-original registerMessageProjection caller inventory.
Prints only package/path/hash/import/export/function identifiers and safe
literals. Never exports original source bodies, prompts, credentials or data.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

ROOT="node_modules/@deepseek-ai/"
TOKEN=b"registerMessageProjection"
MAX_MEMBER=12*1024*1024

def inspect(apk:pathlib.Path):
    require(apk.stat().st_size==SOURCE_BYTES,"APK_SIZE_DRIFT")
    require(file_hash(apk)==SOURCE_SHA,"APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"APK_CRC")
        engine=z.read("assets/engine.bin")
    rows=[]; count=0
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as t:
        for item in t:
            count+=1; require(count<=50000,"TAR_COUNT")
            name=item.name
            if not item.isfile() or not name.startswith(ROOT) or not name.endswith((".js",".mjs",".cjs")):
                continue
            require(0<=item.size<=MAX_MEMBER,"SOURCE_TOO_LARGE")
            f=t.extractfile(item); require(f is not None,"SOURCE_MISSING")
            raw=f.read(MAX_MEMBER+1); require(len(raw)==item.size,"SHORT_SOURCE")
            if TOKEN not in raw: continue
            occ=[]
            start=0
            while True:
                pos=raw.find(TOKEN,start)
                if pos<0: break
                lo=max(0,pos-4500); hi=min(len(raw),pos+2500)
                window=raw[lo:hi]
                funcs=[]
                for m in re.finditer(rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(([^()]{0,300})\)\s*\{",raw[max(0,pos-12000):pos]):
                    fn=m.group(1).decode("utf-8","replace")
                    if fn in ("if","for","while","switch","catch"): continue
                    params=[x.strip() for x in m.group(2).decode("utf-8","replace").split(",")]
                    params=[x for x in params if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,64}",x)]
                    funcs.append({"name":fn,"params":params[:12]})
                classes=[m.group(1).decode("utf-8","replace") for m in re.finditer(
                    rb"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*class\b",
                    raw[:pos])]
                calls=[m.group(1).decode("utf-8","replace") for m in re.finditer(
                    rb"(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(",window)]
                props=[m.group(1).decode("utf-8","replace")+"."+m.group(2).decode("utf-8","replace")
                       for m in re.finditer(rb"\b(this|ctx|sessions|session|projection)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",window)]
                literals=[m.group(1).decode("utf-8","replace") for m in re.finditer(
                    rb"['\"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['\"]",window)]
                occ.append({
                    "offset":pos,
                    "nearestAssignedClasses":classes[-6:],
                    "nearestMethodSignatures":funcs[-8:],
                    "nearbyCalls":sorted(set(calls))[:70],
                    "nearbyPropertyRefs":sorted(set(props))[:70],
                    "nearbySafeLiterals":sorted(set(literals))[:70],
                })
                start=pos+len(TOKEN)
            imports=[]
            for m in re.finditer(rb"""(?:from|import)\s*['"]([^'"]{1,160})['"]""",raw):
                mod=m.group(1).decode("utf-8","replace")
                if mod.startswith("@deepseek-ai/"): imports.append(mod)
            exports=[]
            for m in re.finditer(rb"\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})",raw):
                exports.append(m.group(1).decode("utf-8","replace"))
            parts=name.split("/")
            package="/".join(parts[:3]) if len(parts)>=3 else name
            rows.append({
                "package":package,"path":name,"sha12":sha(raw)[:12],
                "imports":sorted(set(imports))[:40],
                "exports":sorted(set(exports))[:40],
                "occurrences":occ[:20],
            })
    print("P100_MESSAGE_PROJECTION_REGISTRATION_CALLERS="+json.dumps(rows,sort_keys=True))
    print("P100_MESSAGE_PROJECTION_SOURCE_EXPORTED=NO")
    print("P100_MESSAGE_PROJECTION_CALLER_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--original",required=True)
    a=p.parse_args(); inspect(pathlib.Path(a.original))
