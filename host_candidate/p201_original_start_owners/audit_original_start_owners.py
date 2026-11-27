#!/usr/bin/env python3
"""P201 original signed-v138 EngineManager *callsite-to-upstream* provenance.

Read original DEX only. Resolve all eight known direct invocations and at most
three incoming app-method edges per source. A symbolic Java/DEX method reference
is NOT an Android framework callback, actual event dispatch, or trusted Node
owner. Never print operands, original strings, argv, URLs, or user data.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys
import zipfile

ORIGINAL_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
APP="Lcom/dsh/android/"
ENGINE="Lcom/dsh/android/EngineManager;"
TARGETS={"start":"MAIN","probeBoot":"PROBE","runDumpConfig":"CONFIG"}
EXPECT={"MAIN":4,"PROBE":1,"CONFIG":3}
REF=re.compile(r"(L[^\s,;]+;)->([^\s(,]+)\(([^)]*)\)([^\s,\]]+)")
SAFE_OWNER=re.compile(r"^Lcom/dsh/android/[A-Za-z_$][A-Za-z0-9_/$]{0,135};$")
SAFE_NAME=re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,85}$")
MAX_NODES=110000
MAX_EDGES=240000
MAX_PER_METHOD=15000
MAX_UPSTREAM_DEPTH=3
MAX_UPSTREAM_SAMPLES=6

class Blocked(Exception):pass

def need(expr,reason):
    if not expr:raise Blocked("P201_DENY_"+reason)

def normalize_desc(desc):
    return "".join(desc.split())

def key(owner,name,desc):
    return owner,name,normalize_desc(desc)

def hash_id(node):
    return hashlib.sha256("|".join(node).encode("utf-8")).hexdigest()[:16]

def safe_symbol(node):
    owner,name,_=node
    if not SAFE_OWNER.fullmatch(owner) or not SAFE_NAME.fullmatch(name):
        return "REDACTED_SYMBOL_"+hash_id(node)
    return owner[1:-1].replace("/",".")+"."+name

def class_role(owner,method):
    # Heuristics are classifications of symbol names, never run-time evidence.
    base=owner.rsplit("/",1)[-1].rstrip(";").split("$")[0]
    if base.endswith("Activity"):who="ACTIVITY"
    elif base.endswith("Fragment"):who="FRAGMENT"
    elif base.endswith("ViewModel"):who="VIEW_MODEL"
    elif base.endswith("Service"):who="SERVICE"
    elif base.endswith("Application") or base.endswith("App"):who="APPLICATION"
    elif base.endswith("Controller"):who="CONTROLLER"
    elif base.endswith("Receiver"):who="RECEIVER"
    elif base.endswith("Adapter") or base.endswith("View"):who="VIEW"
    elif "EngineManager" in base:who="ENGINE_MANAGER"
    else:who="APP_OTHER"
    if method in ("onClick","onLongClick","onItemClick","onCheckedChanged",
                  "onTextChanged","afterTextChanged","onMenuItemClick"):
        when="USER_EVENT_CALLBACK_SIGNATURE"
    elif method in ("onCreate","onStart","onResume","onNewIntent",
                    "onActivityResult","onDestroy","onStop","onPause",
                    "onViewCreated","onCreateView","onReceive","onBind"):
        when="ANDROID_LIFECYCLE_SIGNATURE"
    elif method in ("run","invoke","invokeSuspend","call","accept",
                    "onChanged","emit") or method.startswith("lambda$"):
        when="ASYNC_OR_FUNCTION_CALLBACK_SIGNATURE"
    else:when="NO_RECOGNIZED_EVENT_SIGNATURE"
    return who,when

def ref_from_output(opcode,operand):
    if not opcode.startswith("invoke-"):return None
    m=REF.search(operand)
    if m is None:return None
    owner,name,args,ret=m.groups()
    return key(owner,name,"("+args+")"+ret)

def decode_original(apk):
    from androguard.core.dex import DEX
    with zipfile.ZipFile(apk) as z:
        need(z.testzip() is None,"ORIGINAL_ZIP_CRC")
        files=sorted(s for s in z.namelist() if re.fullmatch(
            r"classes(?:[2-9][0-9]*)?\.dex",s))
        need("classes.dex" in files and len(files)<=10,"ORIGINAL_CLASSES_DEX_SET")
        for filename in files:
            d=DEX(z.read(filename))
            for c in d.get_classes():
                owner=c.get_name()
                if not owner.startswith(APP):continue
                for m in c.get_methods():
                    if m.get_code() is None:continue
                    node=key(owner,m.get_name(),m.get_descriptor())
                    yield node,((pc,ins.get_name(),ins.get_output())
                                for pc,ins in m.get_instructions_idx())

def build_graph(methods):
    nodes=set()
    incoming=collections.defaultdict(list)
    targets=collections.defaultdict(list)
    edges=0
    for node,instructions in methods:
        need(node not in nodes,"DUPLICATE_METHOD_DEFINITION")
        if not node[0].startswith(APP):
            # decoder_original already filters external packages, but keep
            # this scope invariant for in-memory and synthetic callers too.
            continue
        nodes.add(node)
        need(len(nodes)<=MAX_NODES,"METHOD_BOUND")
        count=0
        for pc,opcode,operand in instructions:
            ref=ref_from_output(opcode,operand)
            if ref is None:continue
            count+=1
            need(count<=MAX_PER_METHOD,"INVOKES_PER_METHOD_BOUND")
            callee_owner,callee_name,_=ref
            if not callee_owner.startswith(APP):continue
            edges+=1
            need(edges<=MAX_EDGES,"GRAPH_EDGE_BOUND")
            incoming[ref].append((node,pc,opcode))
            if callee_owner==ENGINE and callee_name in TARGETS:
                targets[TARGETS[callee_name]].append((node,pc,opcode,ref))
    for mode,count in EXPECT.items():
        need(len(targets[mode])==count,"EXPECTED_"+mode+"_DIRECT_CALLSITES")
    return nodes,incoming,targets,edges

def upstream_for(node,incoming,max_depth=MAX_UPSTREAM_DEPTH):
    need(0<=max_depth<=3,"UPSTREAM_DEPTH_BOUND")
    frontier={node}
    visited={node}
    levels=[]
    for depth in range(1,max_depth+1):
        level=[]
        new=set()
        for m in sorted(frontier):
            for source,pc,opcode in incoming.get(m,()):
                if source in visited:continue
                level.append((source,pc,opcode))
                new.add(source)
        # Stable, bounded *presentation*; keep traversal frontier all bounded
        # by MAX_NODES, not just sample, to avoid false single-path claims.
        level.sort(key=lambda x:(x[0],x[1],x[2]))
        levels.append({
           "depth":depth,"distinct_source_methods":len(new),
           "sample":[{"method_id":hash_id(v[0]),
                      "symbol":safe_symbol(v[0]),
                      "pc":v[1],
                      "role":class_role(v[0][0],v[0][1])[0],
                      "event_signature":class_role(v[0][0],v[0][1])[1]}
                     for v in level[:MAX_UPSTREAM_SAMPLES]]
        })
        if not new:break
        frontier=new
        visited.update(new)
    return levels

def summarize(methods):
    nodes,incoming,targets,edges=build_graph(methods)
    report={"phase":"P201_EXACT_ORIGINAL_V138_STATIC_UPSTREAM_CALLCHAIN",
            "original_sha256":ORIGINAL_SHA,
            "method_count":len(nodes),"app_invoke_edge_count":edges,
            "entry_modes":{},"true_android_ui_event_executed":False,
            "original_engine_coroutine_os_source_attested":False,
            "p184_original_coroutine_handoff_proven":False,
            "original_node_http_ready":False,
            "production_release":"STRUCTURAL_BLOCKED"}
    for mode in ("MAIN","PROBE","CONFIG"):
        entries=[]
        for source,pc,opcode,target in sorted(targets[mode],
                                             key=lambda x:(x[0],x[1])):
            role,event=class_role(source[0],source[1])
            up=upstream_for(source,incoming)
            signature_candidates=sorted({s["event_signature"]
                for level in up for s in level["sample"]
                if s["event_signature"]!="NO_RECOGNIZED_EVENT_SIGNATURE"})
            if event!="NO_RECOGNIZED_EVENT_SIGNATURE":
                signature_candidates.append(event)
            entries.append({
                "caller_id":hash_id(source),
                "symbol":safe_symbol(source),
                "caller_class_role":role,
                "caller_event_signature":event,
                "instruction_pc":pc,
                "invoke_opcode":opcode,
                "matched_direct_target":mode,
                "upstream":up,
                "potential_event_signatures":sorted(set(signature_candidates)),
                "event_executed":"NOT_PROVEN",
                "coroutine_os_identity":"NOT_ATTESTED"})
        report["entry_modes"][mode]=entries
    return report

def fixed_apk(path):
    p=pathlib.Path(path)
    need(p.is_file() and 100_000_000<p.stat().st_size<200_000_000,
         "FIXED_SIGNED_ORIGINAL_REQUIRED")
    sha=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1<<20),b""):sha.update(b)
    need(sha.hexdigest()==ORIGINAL_SHA,"SIGNED_ORIGINAL_SHA256_MISMATCH")
    return p

def main():
    a=argparse.ArgumentParser()
    a.add_argument("signed_original_v138")
    a.add_argument("--report",required=True)
    args=a.parse_args()
    try:
        report=summarize(decode_original(fixed_apk(args.signed_original_v138)))
        pathlib.Path(args.report).write_text(
            json.dumps(report,sort_keys=True,indent=2)+"\n")
        print("P201_ORIGINAL_SIGNED_V138_STATIC_CALLCHAIN=PASS")
        for mode,expected in EXPECT.items():
            entries=report["entry_modes"][mode]
            print("P201_"+mode+"_DIRECT_CALLSITES="+str(len(entries)))
            for i,item in enumerate(entries,1):
                print("P201_"+mode+"_"+str(i)+"_CALLER="+item["symbol"])
                print("P201_"+mode+"_"+str(i)+"_CALLER_ROLE="+item["caller_class_role"])
                print("P201_"+mode+"_"+str(i)+"_EVENT_SIGNATURE="+item["caller_event_signature"])
                print("P201_"+mode+"_"+str(i)+"_UPSTREAM_REACH="+str(
                    sum(x["distinct_source_methods"] for x in item["upstream"])))
                print("P201_"+mode+"_"+str(i)+"_EVENT_EXECUTED=NOT_PROVEN")
        print("P201_REAL_ORIGINAL_KOTLIN_COROUTINE_OS_IDENTITY=NOT_ATTESTED")
        print("P201_ORIGINAL_P184_RECEIPT_TO_REAL_COROUTINE=NOT_WIRED")
        print("P201_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED")
        print("P201_V139=STRUCTURAL_BLOCKED")
    except Blocked as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P201_DENY_ORIGINAL_DEX_OR_GRAPH_UNEXPECTED",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
