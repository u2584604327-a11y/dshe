#!/usr/bin/env python3
"""P100 exact-original RuntimeContextProjection structural contract.
Never emits original source text or user data.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

TARGET="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"
MAX_MEMBER=3_000_000

def find_matching(text,start):
    depth=0; i=start; quote=None; esc=False; line=False; block=False
    while i<len(text):
        ch=text[i]; nx=text[i+1] if i+1<len(text) else ""
        if line:
            if ch=="\n": line=False
            i+=1; continue
        if block:
            if ch=="*" and nx=="/": block=False; i+=2; continue
            i+=1; continue
        if quote:
            if esc: esc=False
            elif ch=="\\": esc=True
            elif ch==quote: quote=None
            i+=1; continue
        if ch=="/" and nx=="/": line=True; i+=2; continue
        if ch=="/" and nx=="*": block=True; i+=2; continue
        if ch in ("'","\"","\`"): quote=ch; i+=1; continue
        if ch=="{": depth+=1
        elif ch=="}":
            depth-=1
            if depth==0: return i
        i+=1
    raise ValueError("UNBALANCED_BRACES")

def safe_project_return_structure(body):
    """Describe original return/retained shapes without emitting source expressions."""
    rows=[]
    for m in re.finditer(r"\\breturn\\s+([^;]{1,500});",body,re.S):
        expr=m.group(1).strip()
        if expr.startswith("{"): kind="object"
        elif expr.startswith("["): kind="array"
        elif re.match(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*\\s*\\(",expr): kind="call"
        elif re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*",expr): kind="reference"
        else: kind="other"
        keys=sorted(set(re.findall(r"(?<![A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]{0,64})\\s*:",expr)))[:35]
        calls=sorted(set(re.findall(r"([A-Za-z_$][A-Za-z0-9_$]{0,64})\\s*\\(",expr)))[:25]
        rows.append({"form":kind,"lexicalObjectKeys":keys,"calledIdentifiers":calls,
                     "referencesSourceEventSeqs":bool(re.search(r"\\bsourceEventSeqs\\b",expr)),
                     "referencesSurfaceOp":bool(re.search(r"\\bsurfaceOp\\b",expr)),
                     "referencesRetained":bool(re.search(r"\\bretained\\b",expr))})
    assigns=[]
    for m in re.finditer(r"this\\.retained\\s*=\\s*([^;]{1,320});",body,re.S):
        rhs=m.group(1).strip()
        category=("object" if rhs.startswith("{") else "array" if rhs.startswith("[")
                  else "nullish" if rhs in ("null","undefined")
                  else "call" if re.match(r"[A-Za-z_$][A-Za-z0-9_$.]*\\s*\\(",rhs)
                  else "reference" if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*",rhs)
                  else "other")
        assigns.append({"valueCategory":category,
                        "referenceName":rhs if category=="reference" and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.]{0,80}",rhs) else None,
                        "lexicalObjectKeys":sorted(set(re.findall(r"([A-Za-z_$][A-Za-z0-9_$]{0,64})\\s*:",rhs)))[:30]})
    return {"returnCount":len(rows),"returnShapes":rows[:12],
            "retainedAssignments":assigns[:12],
            "projectReferencesSourceEventSeqs":bool(re.search(r"\\bsourceEventSeqs\\b",body)),
            "projectReferencesSurfaceOp":bool(re.search(r"\\bsurfaceOp\\b",body)),
            "projectReferencesMessage":bool(re.search(r"\\bmessage\\b",body)),
            "projectReferencesSource":bool(re.search(r"\\bsource\\b",body))}

def safe_contract(body):
    params=[]
    this_fields=sorted(set(re.findall(r"\bthis\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",body)))[:80]
    event_fields=sorted(set(re.findall(r"\bevent\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",body)))[:80]
    calls=[x for x in re.findall(r"(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(",body)
           if x not in ("if","for","while","switch","catch")]
    literals=re.findall(r"""['"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['"]""",body)
    includes=[]
    for m in re.finditer(r"([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})\??\.includes\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})",body):
        includes.append({
            "receiver":m.group(1).replace("?.","."),
            "argument":m.group(2).replace("?.",".")
        })
    comparisons=[]
    for m in re.finditer(r"(event\??\.(?:type|surfaceOp))\s*(===|!==|==|!=)\s*['\"]([A-Za-z0-9_./:-]{1,80})['\"]",body):
        comparisons.append({"field":m.group(1).replace("?.","."),"operator":m.group(2),"value":m.group(3)})
    new_classes=sorted(set(re.findall(r"\bnew\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\b",body)))[:50]
    assigned=sorted(set(re.findall(r"\bthis\.([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=",body)))[:60]
    return {
        "thisFields":this_fields,
        "eventFields":event_fields,
        "calledIdentifiers":sorted(set(calls))[:100],
        "safeLiterals":sorted(set(literals))[:100],
        "includes":includes[:30],
        "eventComparisons":comparisons[:40],
        "newClasses":new_classes,
        "assignedThisFields":assigned,
        "sourceSize":len(body)
    }

def inspect(apk:pathlib.Path):
    require(apk.stat().st_size==SOURCE_BYTES,"APK_SIZE_DRIFT")
    require(file_hash(apk)==SOURCE_SHA,"APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"APK_CRC")
        engine=z.read("assets/engine.bin")
    raw=None
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as t:
        count=0
        for item in t:
            count+=1; require(count<=50000,"TAR_COUNT")
            if item.name!=TARGET: continue
            require(item.isfile() and 0<=item.size<=MAX_MEMBER,"TARGET_SIZE")
            f=t.extractfile(item); require(f is not None,"TARGET_MISSING")
            raw=f.read(MAX_MEMBER+1); require(len(raw)==item.size,"SHORT_TARGET")
            break
    require(raw is not None,"TARGET_NOT_FOUND")
    text=raw.decode("utf-8","strict")
    m=re.search(r"(?:const|let|var)\s+RuntimeContextProjection\s*=\s*class\b[^\{]*\{",text)
    require(m is not None,"RUNTIME_CONTEXT_CLASS_NOT_FOUND")
    open_pos=text.find("{",m.start())
    close_pos=find_matching(text,open_pos)
    body=text[open_pos+1:close_pos]
    methods=[]
    for mm in re.finditer(r"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(([^()]*)\)\s*\{",body):
        name=mm.group(1)
        if name in ("if","for","while","switch","catch"): continue
        method_open=body.find("{",mm.start())
        try: method_close=find_matching(body,method_open)
        except ValueError: continue
        method_body=body[method_open+1:method_close]
        params=[x.strip() for x in mm.group(2).split(",")]
        params=[x for x in params if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,64}",x)]
        row={"name":name,"params":params[:12],"arity":len(params)}
        row.update(safe_contract(method_body))
        if name=="project": row["returnStructure"]=safe_project_return_structure(method_body)
        methods.append(row)
    out={
        "path":TARGET,
        "sha12":sha(raw)[:12],
        "class":"RuntimeContextProjection",
        "classContract":safe_contract(body),
        "methods":methods[:30]
    }
    print("P100_RUNTIME_CONTEXT_PROJECTION_CONTRACT="+json.dumps(out,sort_keys=True))
    print("P100_RUNTIME_CONTEXT_SOURCE_EXPORTED=NO")
    print("P100_RUNTIME_CONTEXT_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--original",required=True)
    a=p.parse_args(); inspect(pathlib.Path(a.original))
