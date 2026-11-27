#!/usr/bin/env python3
"""P203: exact original v138 parent method -> upstream original DEX invocations.

P202 proved four MainActivity start-lambda constructor PCs. Pin those
constructor instructions *and exact callee class* and trace the methods that
call their parent methods. A static edge is NOT an executed Android UI event.
No APK mutation, Kotlin dispatch, Node or external network.
"""
import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/
                      "p201_original_start_owners"))
import audit_original_start_owners as p201

MAIN="Lcom/dsh/android/MainActivity;"
OBS_PARENT="Lcom/dsh/android/MainActivity$observeEngine$1$1;"
PARENTS={
 "BOOT":(MAIN,"bootEngine",26,
         "Lcom/dsh/android/MainActivity$bootEngine$1;"),
 "AUTO_SAFE":(MAIN,"autoEnterSafeMode",104,
         "Lcom/dsh/android/MainActivity$autoEnterSafeMode$1;"),
 "MANUAL_SAFE":(MAIN,"enterSafeMode",104,
         "Lcom/dsh/android/MainActivity$enterSafeMode$1;"),
 "OBSERVE":(OBS_PARENT,"emit",1432,
         "Lcom/dsh/android/MainActivity$observeEngine$1$1$1;"),
}
MAX_DEPTH=4
MAX_SAMPLE=10
MAX_METHODS=p201.MAX_NODES
MAX_EDGES=p201.MAX_EDGES
MAX_CALLS=p201.MAX_PER_METHOD

class Blocked(Exception):pass

def need(ok,reason):
    if not ok:raise Blocked("P203_DENY_"+reason)

def decode_graph(methods):
    definitions=set()
    incoming=collections.defaultdict(list)
    anchors=collections.defaultdict(list)
    seen_coroutines=collections.Counter()
    spawn_modes=collections.Counter()
    edges=0
    for node,instructions in methods:
        if not node[0].startswith(p201.APP):continue
        need(node not in definitions,"DUPLICATE_METHOD")
        definitions.add(node)
        need(len(definitions)<=MAX_METHODS,"METHOD_COUNT")
        if node[1]=="invokeSuspend":
            for tag,(_,_,_,lambda_class) in PARENTS.items():
                if node[0]==lambda_class:seen_coroutines[tag]+=1
        calls=0
        for pc,opcode,operand in instructions:
            ref=p201.ref_from_output(opcode,operand)
            if ref is None:continue
            calls+=1
            need(calls<=MAX_CALLS,"METHOD_INVOKE_LIMIT")
            if ref[0]==p201.ENGINE and ref[1] in p201.TARGETS:
                spawn_modes[p201.TARGETS[ref[1]]]+=1
            if ref[0].startswith(p201.APP):
                incoming[ref].append((node,pc,opcode))
                edges+=1
                need(edges<=MAX_EDGES,"INVOKE_GRAPH_EDGE_LIMIT")
            for tag,(owner,name,anchor_pc,lambda_class) in PARENTS.items():
                if (node[0]==owner and node[1]==name and
                    pc==anchor_pc and opcode.startswith("invoke-direct") and
                    ref[0]==lambda_class and ref[1]=="<init>"):
                    anchors[tag].append((node,pc))
    need(dict(spawn_modes)==p201.EXPECT,"P201_4_1_3_DIRECT_INVOCATIONS")
    for tag in PARENTS:
        need(seen_coroutines[tag]==1,"ORIGINAL_"+tag+"_SUSPEND_CLASS")
        need(len(anchors[tag])==1,"EXACT_"+tag+"_P202_CONSTRUCTOR_PC")
    return definitions,incoming,anchors,edges

def role_of(node):
    owner,name,desc=node
    klass,event=p201.class_role(owner,name)
    # A name hint is not verified against implemented Android interfaces.
    if name.startswith("access$"):hint="KOTLIN_SYNTHETIC_ACCESSOR_SIGNATURE"
    elif name.endswith("$default"):hint="KOTLIN_DEFAULT_BRIDGE_SIGNATURE"
    elif name in ("onClick","onLongClick","onMenuItemClick",
                  "onItemClick","onCheckedChanged"):
        hint="POSSIBLE_USER_CALLBACK_SIGNATURE"
    elif event=="ANDROID_LIFECYCLE_SIGNATURE":
        hint="POSSIBLE_LIFECYCLE_SIGNATURE"
    elif name in ("invoke","invokeSuspend","emit","run","accept"):
        hint="ASYNC_FUNCTION_SIGNATURE"
    else:hint="UNCLASSIFIED_METHOD_SIGNATURE"
    return klass,hint

def inbound_paths(target,incoming,max_depth=MAX_DEPTH):
    need(0<=max_depth<=4,"DEPTH_LIMIT")
    queue=collections.deque([(target,(),0)])
    best_depth={target:0}
    level_counts=collections.Counter()
    report=[]
    edge_seen=set()
    while queue:
        method,path,depth=queue.popleft()
        if depth>=max_depth:continue
        direct=sorted(incoming.get(method,()),key=lambda x:(x[0],x[1]))
        for caller,pc,opcode in direct:
            edge=(method,caller,pc)
            if edge in edge_seen:continue
            edge_seen.add(edge)
            new_depth=depth+1
            level_counts[new_depth]+=1
            if len(report)<100:
                klass,hint=role_of(caller)
                report.append({
                  "depth":new_depth,"source_id":p201.hash_id(caller),
                  "source_symbol":p201.safe_symbol(caller),
                  "call_instruction_pc":pc,
                  "opcode":opcode,"class_role":klass,
                  "event_signature_hint":hint,
                  "event_actually_dispatched":"NOT_PROVEN"})
            if new_depth<max_depth and best_depth.get(caller,999)>new_depth:
                best_depth[caller]=new_depth
                queue.append((caller,path+(p201.hash_id(caller),),new_depth))
    return {
      "incoming_edges_per_depth":{str(k):level_counts[k]
                                  for k in range(1,max_depth+1)},
      "sampled_source_methods":report[:MAX_SAMPLE],
      "distinct_upstream_methods":len(best_depth)-1,
      "direct_caller_count":len(incoming.get(target,())),
      "method_trigger_classified_by_execution":"NOT_PROVEN",
      "indirect_reflection_or_interface_dispatch":"NOT_EXHAUSTIVELY_RESOLVED"}

def analyze(methods):
    defs,incoming,anchors,edges=decode_graph(methods)
    report={"phase":"P203_FIXED_SIGNED_V138_MAINACTIVITY_PARENT_CALLERS",
      "original_signed_v138_sha256":p201.ORIGINAL_SHA,
      "method_count":len(defs),"app_direct_invoke_edges":edges,
      "actual_original_android_ui_interaction":False,
      "genuine_engine_manager_coroutine_invoked":False,
      "os_owner_epoch_attested":False,
      "p184_receipt_to_original_coroutine":False,
      "original_arm64_node_http_ready":False,
      "release":"STRUCTURAL_BLOCKED","parent_callchains":{}}
    for tag in ("BOOT","AUTO_SAFE","MANUAL_SAFE","OBSERVE"):
        node,pc=anchors[tag][0]
        need(node in defs,"PARENT_ORIGINAL_METHOD_MISSING")
        source=p201.safe_symbol(node)
        data=inbound_paths(node,incoming)
        data.update({
            "exact_original_parent_symbol":source,
            "exact_original_parent_descriptor_hash":p201.hash_id(node),
            "p202_constructor_pc":pc,
            "p202_anchor_original_verified":True,
            "actual_coroutine_invocation":"NOT_OBSERVED_BY_STATIC_AUDIT"})
        report["parent_callchains"][tag]=data
    return report

def main():
    a=argparse.ArgumentParser()
    a.add_argument("signed_original_v138")
    a.add_argument("--report",required=True)
    args=a.parse_args()
    try:
        original=p201.fixed_apk(args.signed_original_v138)
        q=analyze(p201.decode_original(original))
        pathlib.Path(args.report).write_text(
            json.dumps(q,sort_keys=True,indent=2)+"\n")
        print("P203_REAL_SIGNED_V138_PARENT_METHOD_UPSTREAM=PASS")
        for tag in ("BOOT","AUTO_SAFE","MANUAL_SAFE","OBSERVE"):
            row=q["parent_callchains"][tag]
            print("P203_"+tag+"_PARENT="+row["exact_original_parent_symbol"])
            print("P203_"+tag+"_DIRECT_INBOUND_CALLS="+str(row["direct_caller_count"]))
            print("P203_"+tag+"_UPSTREAM_METHODS="+str(row["distinct_upstream_methods"]))
            for i,source in enumerate(row["sampled_source_methods"],1):
                print("P203_"+tag+"_UPSTREAM_"+str(i)+"_SOURCE="+source["source_symbol"])
                print("P203_"+tag+"_UPSTREAM_"+str(i)+"_PC="+str(source["call_instruction_pc"]))
                print("P203_"+tag+"_UPSTREAM_"+str(i)+"_EVENT_HINT="+source["event_signature_hint"])
            print("P203_"+tag+"_ACTUAL_UI_EVENT=NOT_PROVEN")
        print("P203_REAL_KOTLIN_COROUTINE_OS_ORIGIN=NOT_ATTESTED")
        print("P203_P184_RECEIPT_TO_ORIGINAL_KOTLIN=NOT_WIRED")
        print("P203_ORIGINAL_NODE_HTTP_READY=NOT_WIRED")
        print("P203_V139=STRUCTURAL_BLOCKED")
    except (Blocked,p201.Blocked) as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P203_DENY_SIGNED_V138_UPSTREAM_DECODER_UNEXPECTED",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
