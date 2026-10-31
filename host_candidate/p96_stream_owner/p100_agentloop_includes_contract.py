#!/usr/bin/env python3
"""P100 exact-original dsh-agent-loop .includes receiver inventory.
Outputs only file paths, hashes and safe receiver identifiers; never source.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

ROOT="node_modules/@deepseek-ai/dsh-agent-loop/"
MAX_MEMBER=3_000_000
RECEIVER=re.compile(rb"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*){0,6})(?:\?\.|\.)includes\s*\(")

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
            details=[]
            for m in RECEIVER.finditer(raw):
                value=m.group(1).decode("utf-8","replace").replace("?.",".")
                if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.]{0,120}",value):
                    continue
                receivers.append(value)
                lo=max(0,m.start()-1800)
                hi=min(len(raw),m.end()+1000)
                window=raw[lo:hi]
                method_candidates=[]
                for mm in re.finditer(
                    rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\([^()]{0,320}\)\s*\{",
                    raw[lo:m.start()]):
                    method_candidates.append(mm.group(1).decode("utf-8","replace"))
                prop_refs=[]
                for pm in re.finditer(
                    rb"\b(event|message|entry|item|decision|session|this)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",
                    window):
                    prop_refs.append(
                        pm.group(1).decode("utf-8","replace")+"."+pm.group(2).decode("utf-8","replace"))
                calls=[]
                for cm in re.finditer(
                    rb"(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(",
                    window):
                    calls.append(cm.group(1).decode("utf-8","replace"))
                class_candidates=[]
                for xm in re.finditer(
                    rb"class\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})",
                    raw[:m.start()]):
                    class_candidates.append(xm.group(1).decode("utf-8","replace"))
                assigned_class_candidates=[]
                for xm in re.finditer(
                    rb"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*class\b",
                    raw[:m.start()]):
                    assigned_class_candidates.append(xm.group(1).decode("utf-8","replace"))
                method_signatures=[]
                for mm in re.finditer(
                    rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(([^()]{0,320})\)\s*\{",
                    raw[max(0,m.start()-12000):m.start()]):
                    name2=mm.group(1).decode("utf-8","replace")
                    if name2 in ("if","for","while","switch","catch"): continue
                    params2=[x.strip() for x in mm.group(2).decode("utf-8","replace").split(",")]
                    params2=[x for x in params2 if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,64}",x)]
                    method_signatures.append({"name":name2,"params":params2[:12]})
                event_type_literals=[]
                for em in re.finditer(
                    rb"event\??\.type\s*(?:===|==|!==|!=)\s*['\"]([A-Za-z0-9_./:-]{1,80})['\"]",
                    window):
                    event_type_literals.append(em.group(1).decode("utf-8","replace"))
                safe_literals=[]
                for sm in re.finditer(
                    rb"['\"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['\"]",
                    window):
                    value2=sm.group(1).decode("utf-8","replace")
                    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_./:-]{1,80}",value2):
                        safe_literals.append(value2)
                arg_match=re.match(
                    rb"\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})\s*\)",
                    raw[m.end():m.end()+240])
                includes_arg=None
                if arg_match:
                    includes_arg=arg_match.group(1).decode("utf-8","replace").replace("?.",".")
                details.append({
                    "receiver":value,
                    "includesArgument":includes_arg,
                    "offset":m.start(),
                    "nearestClasses":class_candidates[-6:],
                    "nearestAssignedClasses":assigned_class_candidates[-6:],
                    "nearestMethodSignatures":method_signatures[-8:],
                    "nearestMethods":method_candidates[-5:],
                    "nearbyEventTypeLiterals":sorted(set(event_type_literals))[:30],
                    "nearbySafeLiterals":sorted(set(safe_literals))[:50],
                    "nearbyPropertyRefs":sorted(set(prop_refs))[:60],
                    "nearbyCalls":sorted(set(calls))[:60],
                })
            if receivers:
                helper_imports=[]
                for im in re.finditer(
                    rb"import\s*\{([^}]{1,1800})\}\s*from\s*['\"]([^'\"]{1,180})['\"]",
                    raw):
                    clause=im.group(1).decode("utf-8","replace")
                    module=im.group(2).decode("utf-8","replace")
                    if any(token in clause for token in (
                        "isReplacementSurfaceEvent","eventsNewestFirst",
                        "createUserMessage","createSystemMessage","textOf")):
                        helper_imports.append({
                            "module":module,
                            "helpers":[token for token in (
                                "isReplacementSurfaceEvent","eventsNewestFirst",
                                "createUserMessage","createSystemMessage","textOf")
                                if token in clause]
                        })
                class_assignments=[]
                for cm in re.finditer(
                    rb"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*class\b",
                    raw[max(0,details[0]["offset"]-20000):details[0]["offset"]]):
                    class_assignments.append(cm.group(1).decode("utf-8","replace"))
                rows.append({
                    "path":name,
                    "sha12":sha(raw)[:12],
                    "includesReceivers":sorted(set(receivers))[:80],
                    "occurrences":len(receivers),
                    "helperImports":helper_imports[:20],
                    "nearestAssignedClasses":class_assignments[-5:],
                    "details":details[:20],
                })
    print("P100_AGENTLOOP_INCLUDES_RECEIVER_INVENTORY="+json.dumps(rows,sort_keys=True))
    print("P100_AGENTLOOP_SOURCE_EXPORTED=NO")
    print("P100_AGENTLOOP_INCLUDES_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--original",required=True)
    a=p.parse_args()
    inspect(pathlib.Path(a.original))
