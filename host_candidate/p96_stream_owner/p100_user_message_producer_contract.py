#!/usr/bin/env python3
"""P100 exact-original AgentLoop user/message producer and append contract.
Outputs structural identifiers only; never source bodies, prompts or user data.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

TARGET="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"
MAX_MEMBER=3_000_000
SAFE_NAME=r"[A-Za-z_$][A-Za-z0-9_$]{0,64}"

def read_target(apk):
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

def owner_meta(raw,pos):
    prefix=raw[:pos]
    classes=[m.group(1).decode("utf-8","replace") for m in re.finditer(
        rb"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*=\s*class\b",prefix)]
    methods=[]
    for m in re.finditer(
        rb"(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(([^()]{0,320})\)\s*\{",
        raw[max(0,pos-16000):pos]):
        name=m.group(1).decode("utf-8","replace")
        if name in ("if","for","while","switch","catch"): continue
        params=[x.strip() for x in m.group(2).decode("utf-8","replace").split(",")]
        params=[x for x in params if re.fullmatch(SAFE_NAME,x)]
        methods.append({"name":name,"params":params[:12]})
    return classes[-5:],methods[-8:]

def window_meta(raw,pos,radius=2600):
    window=raw[max(0,pos-radius):min(len(raw),pos+radius)]
    props=[]
    for m in re.finditer(
        rb"\b(event|message|input|current|rendered|session|this|entry|data)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",
        window):
        props.append(m.group(1).decode()+"."+m.group(2).decode())
    nested=[]
    for m in re.finditer(
        rb"\b(event|message|input|current|rendered|entry)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})\??\.([A-Za-z_$][A-Za-z0-9_$]{0,64})",
        window):
        nested.append(m.group(1).decode()+"."+m.group(2).decode()+"."+m.group(3).decode())
    calls=[m.group(1).decode("utf-8","replace") for m in re.finditer(
        rb"(?:this\.)?([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*\(",window)]
    literals=[m.group(1).decode("utf-8","replace") for m in re.finditer(
        rb"['\"]([A-Za-z][A-Za-z0-9_./:-]{1,80})['\"]",window)]
    object_keys=[m.group(1).decode("utf-8","replace") for m in re.finditer(
        rb"(?:^|[,\{])\s*([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*:",window)]
    return {
        "propertyRefs":sorted(set(props))[:80],
        "nestedPropertyRefs":sorted(set(nested))[:80],
        "calledIdentifiers":sorted(set(calls))[:80],
        "safeLiterals":sorted(set(literals))[:80],
        "objectKeys":sorted(set(object_keys))[:80],
        "mentionsSurfaceOp":b"surfaceOp" in window,
        "mentionsSourceEventSeqs":b"sourceEventSeqs" in window,
    }

def safe_reference_origins(raw,pos,name):
    if not re.fullmatch(SAFE_NAME,name):
        return []
    window_start=max(0,pos-10000)
    window=raw[window_start:pos]
    key=re.escape(name.encode("ascii"))
    chain=rb"([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,6})"
    rows=[]
    patterns=[
        ("decl-call",rb"(?:const|let|var)\s+"+key+rb"\s*=\s*(?:await\s+)?"+chain+rb"\s*\("),
        ("assign-call",rb"\b"+key+rb"\s*=\s*(?:await\s+)?"+chain+rb"\s*\("),
        ("decl-ref",rb"(?:const|let|var)\s+"+key+rb"\s*=\s*"+chain),
        ("assign-ref",rb"\b"+key+rb"\s*=\s*"+chain),
    ]
    for kind,pat in patterns:
        re.compile(pat)
        for m in re.finditer(pat,window):
            value=m.group(1).decode("utf-8","replace").replace("?.",".")
            rows.append({
                "kind":kind,
                "value":value,
                "distance":pos-(window_start+m.start())
            })
    rows.sort(key=lambda row:row["distance"])
    out=[]
    seen=set()
    for row in rows:
        sig=(row["kind"],row["value"])
        if sig in seen: continue
        seen.add(sig); out.append(row)
        if len(out)>=5: break
    return out

def split_call_args(raw,open_pos,max_scan=5000):
    args=[]; start=open_pos+1; i=start
    paren=1; brace=0; bracket=0; quote=None; escaped=False
    limit=min(len(raw),open_pos+max_scan)
    while i<limit:
        ch=raw[i]
        if quote is not None:
            if escaped:
                escaped=False
            elif ch==92:
                escaped=True
            elif ch==quote:
                quote=None
            i+=1; continue
        if ch in (34,39,96):
            quote=ch; i+=1; continue
        if ch==40:
            paren+=1
        elif ch==41:
            paren-=1
            if paren==0:
                args.append(raw[start:i].strip())
                return args
        elif ch==123:
            brace+=1
        elif ch==125:
            brace=max(0,brace-1)
        elif ch==91:
            bracket+=1
        elif ch==93:
            bracket=max(0,bracket-1)
        elif ch==44 and paren==1 and brace==0 and bracket==0:
            args.append(raw[start:i].strip()); start=i+1
        i+=1
    return []

SAFE_EXPR_TOKEN=re.compile(
    rb"[A-Za-z_$][A-Za-z0-9_$]{0,64}|\d+|===|!==|==|!=|<=|>=|\?\?|\?|\:|\.|\[|\]|\{|\}|['\"][A-Za-z0-9_./:-]{1,80}['\"]")

def focus_field_tokens(expr,field):
    key=field.encode("ascii")
    pos=expr.find(key)
    if pos<0: return []
    colon=expr.find(b":",pos+len(key))
    if colon<0 or colon-pos>120: return []
    sample=expr[colon+1:colon+241]
    return [m.group(0).decode("utf-8","replace")
            for m in SAFE_EXPR_TOKEN.finditer(sample)][:60]

def safe_expr_shape(expr):
    s=expr.strip()
    if not s: return {"kind":"empty"}
    if s.startswith(b"{"):
        keys=sorted(set(m.group(1).decode("utf-8","replace") for m in
            re.finditer(rb"(?:^|[,\{])\s*([A-Za-z_$][A-Za-z0-9_$]{0,64})\s*:",s)))[:40]
        return {
            "kind":"object",
            "keys":keys,
            "surfaceOpTokens":focus_field_tokens(s,"surfaceOp"),
            "sourceEventSeqsTokens":focus_field_tokens(s,"sourceEventSeqs")
        }
    if s.startswith(b"["): return {"kind":"array"}
    m=re.fullmatch(rb"['\"]([A-Za-z0-9_./:-]{1,80})['\"]",s)
    if m: return {"kind":"literal","value":m.group(1).decode("utf-8","replace")}
    m=re.match(rb"([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,6})",s)
    if m:
        value=m.group(1).decode("utf-8","replace").replace("?.",".")
        rest=s[m.end():].lstrip()
        return {"kind":"call" if rest.startswith(b"(") else "reference","value":value}
    return {"kind":"other","tokens":[m.group(0).decode("utf-8","replace")
        for m in SAFE_EXPR_TOKEN.finditer(s[:300])][:50]}

def safe_second_arg(segment):
    s=segment.lstrip()
    if not s.startswith(b","):
        return {"kind":"missing-comma"}
    s=s[1:].lstrip()
    if not s:
        return {"kind":"empty"}
    if s.startswith(b"{"): return {"kind":"object"}
    if s.startswith(b"["): return {"kind":"array"}
    m=re.match(rb"['\"]([A-Za-z0-9_./:-]{1,80})['\"]",s)
    if m:
        return {"kind":"literal","value":m.group(1).decode("utf-8","replace")}
    m=re.match(rb"([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})",s)
    if m:
        value=m.group(1).decode("utf-8","replace").replace("?.",".")
        rest=s[m.end():].lstrip()
        return {"kind":"call" if rest.startswith(b"(") else "reference","value":value}
    return {"kind":"other","firstByte":chr(s[0]) if 32<=s[0]<=126 else "NONASCII"}

def safe_field_value(segment,field):
    key=re.escape(field.encode("ascii"))
    m=re.search(key+rb"\s*:\s*['\"]([A-Za-z0-9_./:-]{1,80})['\"]",segment)
    if m:
        return {"kind":"literal","value":m.group(1).decode("utf-8","replace")}
    m=re.search(key+rb"\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*){0,5})",segment)
    if m:
        return {"kind":"reference","value":m.group(1).decode("utf-8","replace").replace("?.",".")}
    m=re.search(key+rb"\s*:\s*([\[{])",segment)
    if m:
        return {"kind":"array" if m.group(1)==b"[" else "object"}
    return {"kind":"absent"}

def inspect(apk):
    raw=read_target(apk)
    appends=[]
    append_pat=re.compile(
        rb"(?:(?:this\.)?session|this\.session)\??\.append\s*\(\s*['\"]([A-Za-z0-9_./:-]{1,80})['\"]")
    matches=list(append_pat.finditer(raw))
    for index,m in enumerate(matches):
        classes,methods=owner_meta(raw,m.start())
        end=min(len(raw),m.end()+1800)
        if index+1<len(matches):
            end=min(end,matches[index+1].start())
        segment=raw[m.end():end]
        open_pos=raw.find(b"(",m.start(),m.end())
        call_args=split_call_args(raw,open_pos) if open_pos>=0 else []
        call_arg_shapes=[safe_expr_shape(arg) for arg in call_args[:6]]
        second_arg=call_arg_shapes[1] if len(call_arg_shapes)>1 else safe_second_arg(segment)
        origins=[]
        if second_arg.get("kind")=="reference":
            origins=safe_reference_origins(raw,m.start(),second_arg.get("value",""))
        appends.append({
            "eventType":m.group(1).decode("utf-8","replace"),
            "offset":m.start(),
            "nearestAssignedClasses":classes,
            "nearestMethodSignatures":methods,
            "secondArgOrigins":origins,
            "callArgCount":len(call_args),
            "callArgShapes":call_arg_shapes,
            "argumentShapes":{
                "secondArg":second_arg,
                "surfaceOp":safe_field_value(segment,"surfaceOp"),
                "sourceEventSeqs":safe_field_value(segment,"sourceEventSeqs"),
                "message":safe_field_value(segment,"message"),
                "source":safe_field_value(segment,"source"),
                "reason":safe_field_value(segment,"reason"),
            },
            "nearby":window_meta(raw,m.start(),1800),
        })
    user_rows=[]
    for m in re.finditer(rb"['\"]user/message['\"]",raw):
        classes,methods=owner_meta(raw,m.start())
        user_rows.append({
            "offset":m.start(),
            "nearestAssignedClasses":classes,
            "nearestMethodSignatures":methods,
            "nearby":window_meta(raw,m.start(),2600),
        })
    print("P100_AGENTLOOP_SESSION_APPEND_CALLS="+json.dumps(appends,sort_keys=True))
    print("P100_AGENTLOOP_USER_MESSAGE_OCCURRENCES="+json.dumps(user_rows,sort_keys=True))
    print("P100_AGENTLOOP_USER_MESSAGE_PRODUCER_SHA12="+sha(raw)[:12])
    print("P100_AGENTLOOP_USER_MESSAGE_SOURCE_EXPORTED=NO")
    print("P100_AGENTLOOP_USER_MESSAGE_PRODUCER_SCAN=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--original",required=True)
    a=p.parse_args(); inspect(pathlib.Path(a.original))
