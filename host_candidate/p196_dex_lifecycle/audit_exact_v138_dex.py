#!/usr/bin/env python3
"""P196: strict symbolic DEX difference of exact signed v138 and P47 DENY APK.

A binary structure comparison, not a proof of live EngineManager, Node/HTTP
readiness or the on-device process owner. On any uncertainty, deny. Never print
instruction operands, constants, argv, environment, private paths or logcat.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile
from dataclasses import dataclass

ORIGINAL_SHA = "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
ORIGINAL_START = "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
BRIDGE = "Lcom/dsh/android/p40/P40ProcessBridge;"
MODES = (
    ("MAIN", "Lcom/dsh/android/EngineManager$start$2;", "invokeSuspend", "start", 3912),
    ("PROBE", "Lcom/dsh/android/EngineManager;", "probeBoot", "probeOrDeny", None),
    ("CONFIG", "Lcom/dsh/android/EngineManager;", "runDumpConfig", "configOrDeny", None),
)
LIFECYCLE_EDGES = {
    3924: "Lcom/dsh/android/EngineManager;->access$setProcess$p(",
    3980: "Lcom/dsh/android/EngineManager$start$2",
    3986: "Ljava/lang/Thread;-><init>(",
    4010: "Ljava/lang/Thread;->start()",
    4026: "Ljava/util/concurrent/CountDownLatch;->await(",
    4674: "Lkotlinx/coroutines/flow/MutableStateFlow;->setValue(",
}

class Denied(Exception):
    pass

def need(condition, reason):
    if not condition:
        raise Denied("P196_DENY_" + reason)

@dataclass(frozen=True)
class Op:
    pc: int
    name: str
    width: int
    operand: str  # intentionally never printed

@dataclass(frozen=True)
class MethodSnapshot:
    name: str
    descriptor: str
    access_flags: int
    layout: tuple
    handlers: tuple
    ops: tuple

def exception_shape(code, dex):
    items=code.get_tries() or []
    need(len(items)==code.get_tries_size(),"TRY_TABLE_COUNT")
    if not items:
        need(code.get_handlers() is None or
             code.get_handlers().get_size()==0, "UNEXPECTED_CATCH_LIST")
        return ()
    handlers=code.get_handlers()
    need(handlers is not None,"MISSING_CATCH_HANDLERS")
    base=handlers.get_off()
    mapping={}
    for h in handlers.get_list():
        key=h.get_off()-base
        need(key>=0 and key not in mapping, "DUPLICATE_CATCH_OFFSET")
        types=tuple((dex.get_cm_type(p.get_type_idx()),p.get_addr())
                    for p in h.get_handlers())
        catch_all=h.get_catch_all_addr() if h.get_size()<=0 else None
        mapping[key]=(types,catch_all)
    answer=[]
    for item in items:
        off=item.get_handler_off()
        need(off in mapping,"UNRESOLVED_CATCH_TARGET")
        answer.append((item.get_start_addr(),item.get_insn_count(),mapping[off]))
    return tuple(answer)

def snapshot(method, dex):
    code=method.get_code()
    need(code is not None,"ORIGINAL_METHOD_WITHOUT_CODE")
    ops=tuple(Op(pc,i.get_name(),i.get_length(),i.get_output())
              for pc,i in method.get_instructions_idx())
    need(0<len(ops)<100_000,"METHOD_INSTRUCTION_BOUNDS")
    need(sum(op.width for op in ops)==code.get_insns_size()*2,
         "METHOD_WIDTH_DRIFT")
    need(all(op.width>0 and op.pc>=0 for op in ops),"NONPOSITIVE_PC_OR_WIDTH")
    return MethodSnapshot(
        method.get_name(),method.get_descriptor(),method.get_access_flags(),
        (code.get_registers_size(),code.get_ins_size(),code.get_outs_size(),
         code.get_tries_size(),code.get_insns_size()),
        exception_shape(code,dex),ops)

def lookup(dex, class_name, method_name):
    matches=[m for c in dex.get_classes() if c.get_name()==class_name
             for m in c.get_methods() if m.get_name()==method_name]
    need(len(matches)==1, "MISSING_OR_AMBIGUOUS_"+method_name.upper())
    return snapshot(matches[0],dex)

def expected_target(bridge_name):
    return BRIDGE+"->"+bridge_name+"(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"

def compare_method(before, after, label, bridge_name, fixed_pc=None):
    need(before.name==after.name and before.descriptor==after.descriptor,
         label+"_METHOD_SIGNATURE_DRIFT")
    need(before.access_flags==after.access_flags,label+"_METHOD_FLAGS_DRIFT")
    need(before.layout==after.layout,label+"_REGISTER_OR_TRY_LAYOUT_DRIFT")
    need(before.handlers==after.handlers,label+"_CATCH_TOPOLOGY_DRIFT")
    need(len(before.ops)==len(after.ops),label+"_INSTRUCTION_COUNT_DRIFT")
    replacements=[]
    for a,b in zip(before.ops,after.ops):
        need(a.pc==b.pc and a.width==b.width,label+"_PC_OR_WIDTH_DRIFT_"+str(a.pc))
        if a==b:
            continue
        bridge=expected_target(bridge_name)
        # Same 35c invoke register set and byte width; only the invocation
        # type and method symbol may change, no new instructions or branches.
        authorized=(a.name=="invoke-virtual" and
                    b.name=="invoke-static" and
                    a.operand.endswith(ORIGINAL_START) and
                    b.operand.endswith(bridge) and
                    a.operand[:-len(ORIGINAL_START)]==
                    b.operand[:-len(bridge)] and
                    a.width==6)
        need(authorized,label+"_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_"+str(a.pc))
        replacements.append(a.pc)
    need(len(replacements)==1,label+"_EXACTLY_ONE_REWRITE_REQUIRED")
    if fixed_pc is not None:
        need(replacements[0]==fixed_pc,label+"_FIXED_ORIGINAL_PC_DRIFT")
    return replacements[0],len(before.ops)

def check_original_lifecycle(main):
    by_pc={op.pc:op for op in main.ops}
    for pc,expected in LIFECYCLE_EDGES.items():
        op=by_pc.get(pc)
        need(op is not None and op.name.startswith("invoke-") and
             expected in op.operand,
             "ORIGINAL_LIFECYCLE_EDGE_DRIFT_PC_"+str(pc))

def exact_original_files(original,derived):
    o=pathlib.Path(original);d=pathlib.Path(derived)
    need(o.is_file() and d.is_file() and o.resolve()!=d.resolve(),
         "TWO_DISTINCT_APK_FILES_REQUIRED")
    need(100_000_000<o.stat().st_size<200_000_000,"ORIGINAL_APK_SIZE")
    need(100_000_000<d.stat().st_size<300_000_000,"DERIVED_APK_SIZE")
    h=hashlib.sha256()
    with o.open("rb") as f:
        for part in iter(lambda:f.read(2<<20),b""):
            h.update(part)
    need(h.hexdigest()==ORIGINAL_SHA,"EXACT_SIGNED_ORIGINAL_SHA")
    return o,d

def protected_asset_hashes(z):
    names=[n for n in z.namelist() if n.startswith(("assets/","lib/"))
           and not n.endswith("/")]
    need(0<len(names)<50_000 and len(names)==len(set(names)),
         "ORIGINAL_ASSET_NAMES")
    return {n:hashlib.sha256(z.read(n)).digest() for n in names}

def audit_files(original,derived):
    o,d=exact_original_files(original,derived)
    from androguard.core.dex import DEX
    with zipfile.ZipFile(o) as a, zipfile.ZipFile(d) as b:
        need(a.testzip() is None and b.testzip() is None,"APK_ZIP_CRC")
        need("classes.dex" in a.namelist() and
             "classes.dex" in b.namelist() and
             "classes2.dex" in a.namelist() and
             "classes2.dex" in b.namelist() and
             "classes3.dex" in b.namelist(),"DEX_123_REQUIRED")
        need(a.read("classes2.dex")==b.read("classes2.dex"),"CLASSES2_DEX_CHANGED")
        need(protected_asset_hashes(a)==protected_asset_hashes(b),
             "ORIGINAL_ASSETS_OR_NATIVE_LIB_DRIFT")
        before=DEX(a.read("classes.dex"))
        after=DEX(b.read("classes.dex"))
    results={}
    for label,clazz,method,bridge,pc in MODES:
        original=lookup(before,clazz,method)
        candidate=lookup(after,clazz,method)
        if label=="MAIN":
            check_original_lifecycle(original)
            check_original_lifecycle(candidate)
        changed,count=compare_method(original,candidate,label,bridge,pc)
        results[label]={"replaced_pc":changed,"instruction_count":count}
    need(len(results)==3,"EXACTLY_THREE_ORIGINAL_MODES")
    return results

def main():
    p=argparse.ArgumentParser()
    p.add_argument("original_signed_v138")
    p.add_argument("derived_ephemeral_p47_denied")
    p.add_argument("--report",required=True)
    args=p.parse_args()
    try:
        results=audit_files(args.original_signed_v138,args.derived_ephemeral_p47_denied)
        report={"phase":"P196_STRICT_ORIGINAL_V138_DEX_SYMBOLIC_DIFF",
                "original_sha256":ORIGINAL_SHA,
                "three_callsite_rewrites":results,
                "engine_manager_coroutine_executed":False,
                "real_node_started":False,
                "production_http_ready":False,
                "production_release":"STRUCTURAL_BLOCKED"}
        pathlib.Path(args.report).write_text(json.dumps(report,indent=2)+"\n")
        print("P196_EXACT_ORIGINAL_V138_MAIN_DEX_SEMANTIC_DIFF=PASS")
        print("P196_THREE_TYPED_P40_CALLSITES_ONLY_REWRITTEN=PASS")
        print("P196_REGISTER_BRANCH_CATCH_LIFECYCLE_PARITY=PASS")
        print("P196_SECONDARY_DEX_ASSET_NATIVE_HASH_PARITY=PASS")
        print("P196_ORIGINAL_COROUTINE_NODE_HTTP_READY=NOT_WIRED")
        print("P196_FORMAL_V139=STRUCTURAL_BLOCKED")
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P196_DENY_UNEXPECTED_DECODER_OR_IO_EXCEPTION",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":
    main()
