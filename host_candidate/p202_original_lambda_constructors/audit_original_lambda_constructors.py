#!/usr/bin/env python3
"""P202 original v138 Kotlin suspend-lambda instantiation provenance.

After P201's verified four EngineManager.start direct callers, trace the
actual original DEX method(s) that construct those four suspend lambda
objects. Do not infer a real click or a trusted coroutine owner from symbols.
Read signed original only; no Node/Android execution, passwords, argv or
original application private data. No unredacted original string operands.
"""
import argparse
import collections
import json
import pathlib
import re
import sys

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/
                      "p201_original_start_owners"))
import audit_original_start_owners as p201

TARGET_LAMBDAS={
 "AUTO_SAFE":"Lcom/dsh/android/MainActivity$autoEnterSafeMode$1;",
 "BOOT":"Lcom/dsh/android/MainActivity$bootEngine$1;",
 "MANUAL_SAFE":"Lcom/dsh/android/MainActivity$enterSafeMode$1;",
 "OBSERVE":"Lcom/dsh/android/MainActivity$observeEngine$1$1$1;",
}
BY_CLASS={v:k for k,v in TARGET_LAMBDAS.items()}
INSTANCE_REF=re.compile(r"Lcom/dsh/android/[A-Za-z0-9_$/]+;")
MAX_NODES=p201.MAX_NODES
MAX_EDGES=p201.MAX_EDGES
MAX_CTORS=128

class Blocked(Exception):pass

def need(ok,reason):
    if not ok:raise Blocked("P202_DENY_"+reason)

def snapshot(methods,require_complete=True):
    nodes=set()
    incoming=collections.defaultdict(list)
    constructs=collections.defaultdict(list)
    allocations=collections.defaultdict(list)
    lambda_main_seen=collections.Counter()
    engine_target_counts=collections.Counter()
    edge_count=0
    for source,instructions in methods:
        if not source[0].startswith(p201.APP):
            continue
        need(source not in nodes,"DUPLICATE_ORIGINAL_METHOD")
        nodes.add(source)
        need(len(nodes)<=MAX_NODES,"ORIGINAL_METHOD_COUNT")
        if source[0] in BY_CLASS and source[1]=="invokeSuspend":
            lambda_main_seen[BY_CLASS[source[0]]]+=1
        for pc,opcode,operand in instructions:
            if opcode=="new-instance":
                for owner in INSTANCE_REF.findall(operand):
                    if owner in BY_CLASS:
                        tag=BY_CLASS[owner]
                        allocations[tag].append((source,pc))
                        need(len(allocations[tag])<=MAX_CTORS,"ALLOCATION_BOUND")
            target=p201.ref_from_output(opcode,operand)
            if target is None or not target[0].startswith(p201.APP):
                continue
            edge_count+=1
            need(edge_count<=MAX_EDGES,"GRAPH_EDGE_BOUND")
            incoming[target].append((source,pc,opcode))
            if target[0]==p201.ENGINE and target[1] in p201.TARGETS:
                engine_target_counts[p201.TARGETS[target[1]]]+=1
            if target[0] in BY_CLASS and target[1]=="<init>":
                tag=BY_CLASS[target[0]]
                constructs[tag].append((source,pc))
                need(len(constructs[tag])<=MAX_CTORS,"CONSTRUCTOR_BOUND")
    if require_complete:
        need(dict(engine_target_counts)==p201.EXPECT,
             "ORIGINAL_P201_4_1_3_DIRECT_CALL_COUNTS")
        for tag in TARGET_LAMBDAS:
            need(lambda_main_seen[tag]==1,
                 "UNIQUE_"+tag+"_ORIGINAL_INVOKESUSPEND")
    return nodes,incoming,constructs,allocations,engine_target_counts

def describe(methods,strict=True):
    nodes,incoming,constructs,allocations,counts=snapshot(
        methods,require_complete=strict)
    report={
      "phase":"P202_ORIGINAL_SIGNED_V138_COROUTINE_CONSTRUCTOR_PROVENANCE",
      "original_sha256":p201.ORIGINAL_SHA,
      "original_start_callsites_verified":(
          dict(counts)==p201.EXPECT if strict else False),
      "lambda_origins":{},
      "real_android_button_tapped":False,
      "actual_original_coroutine_executed":False,
      "real_os_owner_generation_attested":False,
      "p184_receipt_delivered_to_real_coroutine":False,
      "arm64_node_fd_http_ready":False,
      "release":"STRUCTURAL_BLOCKED"}
    for tag in TARGET_LAMBDAS:
        ctor=sorted(set(constructs[tag]),key=lambda v:(v[0],v[1]))
        allocation=sorted(set(allocations[tag]),key=lambda v:(v[0],v[1]))
        items=[]
        for caller,pc in ctor:
            role,shape=p201.class_role(caller[0],caller[1])
            inbound=p201.upstream_for(caller,incoming,max_depth=3)
            roots=[{"depth":x["depth"],"count":x["distinct_source_methods"],
                    "sample":x["sample"][:p201.MAX_UPSTREAM_SAMPLES]}
                   for x in inbound]
            items.append({
                "caller_id":p201.hash_id(caller),
                "caller_symbol":p201.safe_symbol(caller),
                "pc":pc,"caller_role":role,
                "caller_event_signature":shape,
                "exact_inbound_methods":roots,
                "actual_event_executed":"NOT_PROVEN"})
        report["lambda_origins"][tag]={
          "original_suspend_class":p201.safe_symbol(
              (TARGET_LAMBDAS[tag],"invokeSuspend",
               "(Ljava/lang/Object;)Ljava/lang/Object;")),
          "constructor_site_count":len(ctor),
          "allocation_site_count":len(allocation),
          "constructor_sources":items,
          "constructed_in_this_android_session":"NOT_PROVEN",
          "original_ui_event_dispatched":"NOT_PROVEN"}
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument("original_signed_v138")
    p.add_argument("--report",required=True)
    a=p.parse_args()
    try:
        original=p201.fixed_apk(a.original_signed_v138)
        report=describe(p201.decode_original(original))
        pathlib.Path(a.report).write_text(
            json.dumps(report,sort_keys=True,indent=2)+"\n")
        print("P202_ACTUAL_ORIGINAL_V138_FOUR_LAMBDAS_AND_CALLCHAIN=PASS")
        for tag in TARGET_LAMBDAS:
            item=report["lambda_origins"][tag]
            print("P202_"+tag+"_CONSTRUCTOR_CALLSITES="+str(
                  item["constructor_site_count"]))
            print("P202_"+tag+"_NEW_INSTANCE_SITES="+str(
                  item["allocation_site_count"]))
            for n,site in enumerate(item["constructor_sources"],1):
                print("P202_"+tag+"_CONSTRUCTOR_"+str(n)+"_SOURCE="+
                      site["caller_symbol"])
                print("P202_"+tag+"_CONSTRUCTOR_"+str(n)+"_PC="+
                      str(site["pc"]))
                print("P202_"+tag+"_CONSTRUCTOR_"+str(n)+
                      "_EXECUTED=NOT_PROVEN")
        print("P202_REAL_UI_EVENT_DISPATCH=NOT_PROVEN")
        print("P202_REAL_ORIGINAL_KOTLIN_COROUTINE=NOT_EXECUTED")
        print("P202_OS_OWNER_EPOCH_AND_P184_REAL_COROUTINE=NOT_ATTESTED")
        print("P202_ORIGINAL_NODE_HTTP_READY=NOT_WIRED")
        print("P202_V139=STRUCTURAL_BLOCKED")
    except (Blocked,p201.Blocked) as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P202_DENY_BINARY_DECODER_OR_REPORT_ERROR",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
