#!/usr/bin/env python3
"""P204: signed v138 MainActivity.onCreate PC430 normal-edge CFG audit.

This proves original branch *structure*, not which branch Android actually
took. It never modifies, launches or instruments the original runtime.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys
import zipfile

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/
                      "p201_original_start_owners"))
import audit_original_start_owners as p201

MAIN="Lcom/dsh/android/MainActivity;"
ONCREATE="onCreate"
ONCREATE_DESC="(Landroid/os/Bundle;)V"
CALL_PC=430
CALL_NAME="bootEngine"
MAX_INSTRUCTIONS=12000
MAX_BRANCHES=3000
MAX_CONDITION_SAMPLE=20
MAX_NEARBY=24

class Blocked(Exception):pass

def require(ok,label):
    if not ok:raise Blocked("P204_DENY_"+label)

def instruction(pc,op,length,delta=None,callee=None):
    return {"pc":pc,"op":op,"length":length,"delta":delta,"callee":callee}

def is_cond(op):
    return op.startswith("if-")
def is_jump(op):
    return op in ("goto","goto/16","goto/32")
def is_switch(op):
    return op in ("packed-switch","sparse-switch")
def terminates(op):
    return op.startswith("return") or op in ("throw","throw-verification-error")

def validate_instructions(items):
    require(0<len(items)<=MAX_INSTRUCTIONS,"INSTRUCTION_COUNT")
    pcs={x["pc"] for x in items}
    require(len(pcs)==len(items),"DUPLICATE_INSTRUCTION_PC")
    require(items[0]["pc"]==0,"METHOD_NOT_AT_ZERO")
    require(all(type(x["pc"]) is int and x["pc"]>=0 and
                type(x["length"]) is int and x["length"]>0 and
                x["length"]%2==0 and x["length"]<=65536
                for x in items),"INVALID_INSTRUCTION_LENGTH")
    require(all(items[i]["pc"]+items[i]["length"]==items[i+1]["pc"]
                for i in range(len(items)-1)),"INSTRUCTION_GAP_OR_OVERLAP")
    branches=sum(is_cond(x["op"]) or is_jump(x["op"]) or is_switch(x["op"])
                 for x in items)
    require(branches<=MAX_BRANCHES,"TOO_MANY_BRANCHES")
    return pcs

def graph(items):
    pcs=validate_instructions(items)
    by_pc={x["pc"]:x for x in items}
    edges={}
    unknown=[]
    for x in items:
        op,pc=x["op"],x["pc"]
        next_pc=pc+x["length"]
        fall=next_pc if next_pc in pcs else None
        if is_cond(op) or is_jump(op):
            d=x["delta"]
            require(type(d) is int and -(2**31)<=d<2**31,
                    "BAD_BRANCH_OFFSET")
            target=pc+2*d
            require(target in pcs,"BRANCH_NOT_ON_INSTRUCTION")
            if is_cond(op):
                require(fall is not None,"CONDITION_MISSING_FALLTHROUGH")
                edges[pc]=tuple(sorted({target,fall}))
            else:edges[pc]=(target,)
        elif terminates(op):
            edges[pc]=()
        elif is_switch(op):
            # Switch payload instructions are DATA, not fallthrough code.
            # The conservative graph does not expand case offsets.
            unknown.append(pc)
            edges[pc]=(fall,) if fall is not None else ()
        elif op.startswith("fill-array-data") or op.endswith("-payload"):
            unknown.append(pc)
            edges[pc]=(fall,) if fall is not None else ()
        else:edges[pc]=(fall,) if fall is not None else ()
    return edges,unknown,by_pc

def reachable(edges,start,goal,excluded_edge=None):
    todo=[start]
    seen=set()
    while todo:
        at=todo.pop()
        if at==goal:return True
        if at in seen:continue
        seen.add(at)
        for dest in edges.get(at,()):
            if excluded_edge==(at,dest):continue
            if dest not in seen:todo.append(dest)
    return False

def branch_assessment(items):
    edges,unknown,by_pc=graph(items)
    require(CALL_PC in by_pc,"PC430_NOT_AN_INSTRUCTION")
    call=by_pc[CALL_PC]
    ref=call.get("callee")
    require(call["op"].startswith("invoke-") and ref is not None and
        ref[0]==MAIN and ref[1]==CALL_NAME,
        "PC430_NOT_ORIGINAL_BOOTENGINE_INVOKE")
    require(type(ref[2]) is str and ref[2].startswith("("),
            "INVALID_BOOTENGINE_DESCRIPTOR")
    # Enforce uniqueness of this exact bootEngine edge in onCreate
    require(sum(1 for x in items if x.get("callee") is not None and
       x["callee"][0]==MAIN and x["callee"][1]==CALL_NAME)==1,
       "ONCREATE_BOOTENGINE_EDGE_COUNT")

    path=reachable(edges,0,CALL_PC)
    pcs=[x["pc"] for x in items]
    prev=pcs.index(CALL_PC)
    before=items[max(0,prev-MAX_NEARBY):prev]
    candidates=[]
    for row in items:
        pc=row["pc"]
        if (pc>=CALL_PC or not is_cond(row["op"]) or
                not reachable(edges,0,pc)):
            continue
        destinations=edges[pc]
        need_arms=[reachable(edges,d,CALL_PC) for d in destinations]
        needed=[reachable(edges,0,CALL_PC,excluded_edge=(pc,d))
                for d in destinations]
        # From the start, can a single branch exit be removed and still
        # reach the call? Even if not, runtime branch choice remains unknown.
        if len(set(need_arms))>1 or not all(needed):
            category=("SPLIT_REACHABILITY" if len(set(need_arms))>1
                      else "EDGE_REMOVAL_REDUCES_REACHABILITY")
            candidates.append({
                "pc":pc,"opcode":row["op"],"successor_pcs":list(destinations),
                "successor_can_reach_pc430":need_arms,
                "pc430_reachable_when_edge_removed":needed,
                "candidate_kind":category,"runtime_arm_taken":"NOT_OBSERVED",
                "source_boolean_semantics":"NOT_DECODED"})
    candidates.sort(key=lambda x:x["pc"])
    # Reporting safety: only numeric PC/opcode, never original operand/strings.
    nearby=[{"pc":x["pc"],"opcode":x["op"]} for x in before]
    return {
        "original_signed_v138_sha256":p201.ORIGINAL_SHA,
        "method":"MainActivity.onCreate(Bundle)",
        "callsite_pc":CALL_PC,
        "callsite_opcode":call["op"],
        "call_target":"MainActivity.bootEngine",
        "call_descriptor_sha256_16":hashlib.sha256(
            ref[2].encode()).hexdigest()[:16],
        "normal_path_reachability":("REACHABLE_IN_CONSERVATIVE_CFG"
                                    if path else "NOT_REACHED_IN_MODELED_CFG"),
        "switch_or_payload_edges_unexpanded":bool(unknown),
        "exception_handler_edges_unexpanded":True,
        "possible_conditions_bypassing_callsite":candidates[-MAX_CONDITION_SAMPLE:],
        "total_potential_condition_branches":len(candidates),
        "immediately_prior_opcodes":nearby,
        "original_android_pc430_executed":"NOT_OBSERVED",
        "original_coroutine_os_owner_generation":"NOT_ATTESTED",
        "original_p184_receipt_to_coroutine":"NOT_WIRED",
        "original_arm64_node_http_ready":"NOT_WIRED",
        "release":"STRUCTURAL_BLOCKED"
    }

def read_original_oncreate(apk):
    from androguard.core.dex import DEX
    hits=[]
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,"ORIGINAL_ZIP_CRC")
        for filename in sorted(x for x in z.namelist() if
            re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",x)):
            dex=DEX(z.read(filename))
            for c in dex.get_classes():
                if c.get_name()!=MAIN:continue
                for m in c.get_methods():
                    if (m.get_name()==ONCREATE and
                        p201.normalize_desc(m.get_descriptor())==ONCREATE_DESC):
                        rows=[]
                        for pc,i in m.get_instructions_idx():
                            op=i.get_name()
                            delta=(i.get_ref_off() if
                                is_cond(op) or is_jump(op) else None)
                            method_ref=p201.ref_from_output(op,i.get_output())
                            rows.append(instruction(pc,op,i.get_length(),
                                                    delta,method_ref))
                        hits.append(rows)
    require(len(hits)==1,"EXACT_SINGLE_ORIGINAL_ONCREATE")
    return hits[0]

def main():
    a=argparse.ArgumentParser()
    a.add_argument("signed_original_v138")
    a.add_argument("--report",required=True)
    args=a.parse_args()
    try:
        original=p201.fixed_apk(args.signed_original_v138)
        result=branch_assessment(read_original_oncreate(original))
        pathlib.Path(args.report).write_text(
            json.dumps(result,sort_keys=True,indent=2)+"\n")
        print("P204_ORIGINAL_ONCREATE_PC430_EXACT_INVOKE=PASS")
        print("P204_PC430_NORMAL_CFG="+result["normal_path_reachability"])
        print("P204_POTENTIAL_GUARD_COUNT="+str(
              result["total_potential_condition_branches"]))
        for i,row in enumerate(result["possible_conditions_bypassing_callsite"],1):
            print("P204_GUARD_"+str(i)+"_PC="+str(row["pc"]))
            print("P204_GUARD_"+str(i)+"_OPCODE="+row["opcode"])
            print("P204_GUARD_"+str(i)+"_SUCCESSORS="+
                  ",".join(map(str,row["successor_pcs"])))
            print("P204_GUARD_"+str(i)+"_RUNTIME_ARM=NOT_OBSERVED")
        print("P204_SWITCH_CASES="+("UNEXPANDED" if
              result["switch_or_payload_edges_unexpanded"] else "NONE_FOUND"))
        print("P204_EXCEPTION_EDGES=NOT_MODELED")
        print("P204_PC430_ACTUAL_ANDROID_EXECUTION=NOT_OBSERVED")
        print("P204_REAL_COROUTINE_OS_OWNER=NOT_ATTESTED")
        print("P204_ORIGINAL_P184_RECEIPT=NOT_WIRED")
        print("P204_ORIGINAL_NODE_HTTP_READY=NOT_WIRED")
        print("P204_V139=STRUCTURAL_BLOCKED")
    except (Blocked,p201.Blocked) as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P204_DENY_SIGNED_ORIGINAL_CFG_DECODER_UNEXPECTED",
              file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
