#!/usr/bin/env python3
"""P104 SHA-pinned v135→v138 APK entry lineage; read-only metadata, no asset export.

This proves entry identity or differences for two exact signed APKs; it does NOT
prove which older upstream build was used or any native-tool production wiring.
"""
import argparse
import hashlib
import io
import pathlib
import re
import struct
import zipfile

SOURCES = {
    "v135": ("394adfbe85b81ce46c285b1c531ffa307432d777e17af04fe5418272c5cc2e99", 147351542),
    "v138": ("3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5", 147341486),
}
MAX_ENTRIES=2000
MAX_UNCOMPRESSED=750*1024*1024
MAX_ENTRY=350*1024*1024
CHUNK=1024*1024

def require(ok, label):
    if not ok: raise ValueError("P104_FAIL_CLOSED_"+label)

def file_sha(path):
    digest=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(CHUNK),b""):
            digest.update(chunk)
    return digest.hexdigest()

def audit_zip(path, expected):
    sha, length=expected
    require(path.is_file() and path.stat().st_size==length,"APK_SIZE")
    require(file_sha(path)==sha,"APK_SHA256")
    with zipfile.ZipFile(path,"r") as z:
        items=z.infolist()
        require(0<len(items)<=MAX_ENTRIES,"ENTRY_COUNT")
        names=[i.filename for i in items]
        require(len(names)==len(set(names)),"DUPLICATE_NAMES")
        require(all(not n.startswith("/") and
                    not any(s==".." for s in n.split("/")) for n in names),
                "UNSAFE_ENTRY_NAME")
        require(sum(i.file_size for i in items)<=MAX_UNCOMPRESSED,"TOTAL_UNCOMPRESSED_LIMIT")
        result={}
        for info in items:
            require(0<=info.file_size<=MAX_ENTRY,"ENTRY_SIZE")
            digest=hashlib.sha256()
            remaining=info.file_size
            with z.open(info, "r") as f:
                while True:
                    data=f.read(min(CHUNK,remaining+1))
                    if not data: break
                    require(len(data)<=remaining,"STREAM_SIZE_EXCEEDED")
                    remaining-=len(data)
                    digest.update(data)
            require(remaining==0,"TRUNCATED_ENTRY")
            result[info.filename]=(info.file_size,digest.hexdigest())
        return result

def delta(a,b):
    keys=set(a)|set(b)
    common=set(a)&set(b)
    unchanged={n for n in common if a[n]==b[n]}
    changed=sorted(common-unchanged)
    removed=sorted(set(a)-set(b))
    added=sorted(set(b)-set(a))
    return len(keys),len(common),len(unchanged),changed,added,removed

def selftest():
    with zipfile.ZipFile(io.BytesIO(),mode="w") as _:
        pass
    a={"A":(1,"a"),"B":(3,"b")}
    b={"A":(1,"a"),"B":(3,"c"),"C":(4,"d")}
    assert delta(a,b)==(3,2,1,["B"],["C"],[])
    try:require(False,"TEST")
    except ValueError as exc:assert str(exc)=="P104_FAIL_CLOSED_TEST"
    else:raise AssertionError("No gate")
    print("P104_LINEAGE_AUDITOR_SELFTEST=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--v135",type=pathlib.Path)
    p.add_argument("--v138",type=pathlib.Path)
    p.add_argument("--selftest",action="store_true")
    args=p.parse_args()
    if args.selftest: selftest();return
    require(args.v135 is not None and args.v138 is not None,"INPUTS_REQUIRED")
    a=audit_zip(args.v135,SOURCES["v135"])
    b=audit_zip(args.v138,SOURCES["v138"])
    union,shared,unchanged,changed,added,removed=delta(a,b)
    require(shared>0,"NO_SHARED_ENTRIES")
    # DEX and asset results are observable identity only; no executable or
    # instructions are patched, copied, dumped or decompiled.
    dex_summary=[]
    for name in sorted(set(a)|set(b)):
        if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",name):
            dex_summary.append(name+":"+("SAME" if a.get(name)==b.get(name) else "DIFFERENT"))
    print("P104_V135_APK_HASH_AND_SIZE=PASS")
    print("P104_V138_APK_HASH_AND_SIZE=PASS")
    print("P104_SHARED_ENTRY_COUNT="+str(shared))
    print("P104_IDENTICAL_ENTRY_COUNT="+str(unchanged))
    print("P104_CHANGED_ENTRY_COUNT="+str(len(changed)))
    print("P104_ADDED_ENTRY_COUNT="+str(len(added)))
    print("P104_REMOVED_ENTRY_COUNT="+str(len(removed)))
    print("P104_CHANGED_PATHS="+repr(changed[:100]))
    print("P104_ADDED_PATHS="+repr(added[:100]))
    print("P104_REMOVED_PATHS="+repr(removed[:100]))
    print("P104_DEX_ENTRY_IDENTITY="+",".join(dex_summary))
    print("P104_V135_TO_V138_SAME_BINARY=NO")
    print("P104_V91_UPSTREAM_APK_DIRECT_PARENT=NOT_PROVEN")
    print("P104_ORIGINAL_DSH_NATIVE_TOOL_BINDER_PRODUCTION=NOT_WIRED")
    print("P104_APK_DATA_OR_SIGNING_CHANGED=NO")
    # Fail closed if the inputs do not look like closely related APKs,
    # rather than laundering coincidental package name into ancestry.
    require(unchanged>=900,"ENTRY_OVERLAP_INSUFFICIENT")
    print("P104_V135_V138_MOST_ENTRIES_SAME=PASS_LIMITED")

if __name__=="__main__":
    main()
