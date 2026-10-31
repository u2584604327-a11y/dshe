#!/usr/bin/env python3
"""P100 exact-original requestSurfaceGeneration structural scan.
Outputs only identifiers/operators/safe literals, never source bodies.
"""
import argparse,gzip,io,json,pathlib,re,tarfile,zipfile
from p96_original_engine_owner import SOURCE_BYTES,SOURCE_SHA,file_hash,require,sha
TARGET="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"
MAX_MEMBER=3_000_000
TOKEN=b"requestSurfaceGeneration"

SAFE_TOKEN=re.compile(rb"""[A-Za-z_$][A-Za-z0-9_$]{0,64}|\d+|===|!==|==|!=|\+\+|--|\+=|-=|=>|\?|:|\.|\+|-|\*|/|['"][A-Za-z0-9_./:-]{1,80}['"]""")

def read(apk):
    require(apk.stat().st_size==SOURCE_BYTES,"APK_SIZE_DRIFT")
    require(file_hash(apk)==SOURCE_SHA,"APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"APK_CRC")
        engine=z.read("assets/engine.bin")
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as t:
        count=0
        for item in t:
            count+=1; require(count<=50000,"TAR_COUNT")
            if item.name!=TARGET: continue
            require(item.isfile() and 0<=item.size<=MAX_MEMBER,"TARGET_SIZE")
            f=t.extractfile(item); require(f is not None,"TARGET_MISSING")
            raw=f.read(MAX_MEMBER+1); require(len(raw)==item.size,"SHORT_TARGET")
            return raw
    raise AssertionError("TARGET_NOT_FOUND")

def method_owner(raw,pos):
    prefix=raw[max(0,pos-14000):pos]
    rows=[]
    for m in re.finditer(rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(([^()]{0,320})\)\s*\{",prefix):
        name=m.group(1).decode()
        if name in ("if","for","while","switch","catch"): continue
        params=[x.strip() for x in m.group(2).decode("utf-8","replace").split(",")]
        params=[x for x in params if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,64}",x)]
        rows.append({"name":name,"params":params[:10]})
    return rows[-6:]

def tokenized(expr):
    return [m.group(0).decode("utf-8","replace") for m in SAFE_TOKEN.finditer(expr)][:60]

def inspect(apk):
    raw=read(apk)
    rows=[]; start=0
    while True:
        pos=raw.find(TOKEN,start)
        if pos<0: break
        lo=max(0,pos-450); hi=min(len(raw),pos+550)
        window=raw[lo:hi]
        assignments=[]
        for m in re.finditer(rb"this\.requestSurfaceGeneration\s*(=|\+=|-=|\+\+|--)",window):
            rhs=window[m.end():m.end()+160].split(b";",1)[0].split(b"\n",1)[0]
            assignments.append({"op":m.group(1).decode(),"rhsTokens":tokenized(rhs)})
        comparisons=[]
        for m in re.finditer(rb"this\.requestSurfaceGeneration\s*(===|!==|==|!=|<=|>=|<|>)\s*([A-Za-z_$][A-Za-z0-9_$]{0,64}|\d+)",window):
            comparisons.append({"op":m.group(1).decode(),"rhs":m.group(2).decode()})
        surface_exprs=[]
        for m in re.finditer(rb"surfaceOp\s*:\s*([^,}\n]{1,220})",window):
            surface_exprs.append(tokenized(m.group(1)))
        event_types=[m.group(1).decode() for m in re.finditer(
            rb"(?:session\??\.append|this\.session\??\.append)\s*\(\s*['\"]([A-Za-z0-9_./:-]{1,80})['\"]",
            window)]
        rows.append({
            "offset":pos,
            "owners":method_owner(raw,pos),
            "assignments":assignments,
            "comparisons":comparisons,
            "surfaceOpExpressions":surface_exprs,
            "nearbyAppendEventTypes":sorted(set(event_types)),
        })
        start=pos+len(TOKEN)
    print("P100_REQUEST_SURFACE_GENERATION_CONTRACT="+json.dumps({
        "path":TARGET,"sha12":sha(raw)[:12],"occurrences":rows
    },sort_keys=True))
    print("P100_REQUEST_SURFACE_GENERATION_SOURCE_EXPORTED=NO")
    print("P100_REQUEST_SURFACE_GENERATION_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--original",required=True)
    a=p.parse_args();inspect(pathlib.Path(a.original))
