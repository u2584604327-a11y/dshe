#!/usr/bin/env python3
"""P198 read-only original v138 *CALLER* graph (not another callee bytecode diff).

Only fixed signed v138 APK. Detect exact direct dispatch to EngineManager
start/probe/config, and original coroutine class. Never emit invocation
registers, launch argv, URLs, DEX string literals, filesystem, secrets, or
other private app data. A static caller graph is NOT run-time authority.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile
from collections import defaultdict

SIGNED_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
APP_PREFIX="Lcom/dsh/android/"
TARGET_OWNER="Lcom/dsh/android/EngineManager;"
ENGINE_COROUTINE="Lcom/dsh/android/EngineManager$start$2;"
TARGETS={"start":"MAIN","probeBoot":"PROBE","runDumpConfig":"CONFIG"}
INVOKE_REF=re.compile(r"(L[^\s,;]+;)->([^\s(,]+)\(([^)]*)\)")
MAX_CALLS_PER_METHOD=25000
MAX_METHODS=150000
MAX_HITS=2000

class Block(Exception):pass

def require(condition,reason):
    if not condition:raise Block("P198_DENY_"+reason)

def fixed_original(apk):
    p=pathlib.Path(apk)
    require(p.is_file() and 100_000_000<p.stat().st_size<200_000_000,
            "EXACT_ORIGINAL_FILE_REQUIRED")
    sha=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1<<20),b""):
            sha.update(chunk)
    require(sha.hexdigest()==SIGNED_SHA,"ORIGINAL_SIGNED_SHA_MISMATCH")
    return p

def callable_category(owner):
    # Categories only; no class names/arguments/URLs enter CI summary.
    if owner==TARGET_OWNER:return "ENGINE_MANAGER_INTERNAL"
    if owner.startswith(ENGINE_COROUTINE):return "ENGINE_COROUTINE"
    if "Activity;" in owner or "Activity$" in owner:return "ACTIVITY_CALLER"
    if "Service;" in owner or "Service$" in owner:return "SERVICE_CALLER"
    if owner.startswith(APP_PREFIX):return "ORIGINAL_APP_OTHER"
    return "EXTERNAL_OR_UNKNOWN"

def scan_stream(methods):
    """Methods: (owner, method_name, instruction iterable) for synthetic tests and DEX."""
    result={mode:[] for mode in TARGETS.values()}
    all_count=0
    coroutine_found=0
    for owner,name,instructions in methods:
        all_count+=1
        require(all_count<=MAX_METHODS,"ORIGINAL_METHOD_BOUND")
        if owner==ENGINE_COROUTINE and name=="invokeSuspend":
            coroutine_found+=1
        seen=0
        for pc,opcode,operand in instructions:
            if not opcode.startswith("invoke-"):
                continue
            seen+=1
            require(seen<=MAX_CALLS_PER_METHOD,"INVOKES_PER_METHOD_BOUND")
            match=INVOKE_REF.search(operand)
            if not match:continue
            callee,callee_method,_=match.groups()
            if callee!=TARGET_OWNER or callee_method not in TARGETS:
                continue
            mode=TARGETS[callee_method]
            # A static call is directly provable. It does not prove Android
            # dispatch, an actual invocation, OS-origin or coroutine identity.
            record={"owner_category":callable_category(owner),
                    "source_method_bucket":"COROUTINE_METHOD" if name=="invokeSuspend" else "OTHER_METHOD",
                    "caller_id_hash":hashlib.sha256((owner+"->"+name).encode()).hexdigest()[:16],
                    "pc":pc}
            result[mode].append(record)
            require(sum(len(v) for v in result.values())<=MAX_HITS,
                    "DIRECT_CALLSITE_BOUND")
    require(coroutine_found==1,"EXACTLY_ONE_ENGINE_COROUTINE")
    return result

def decoder_methods(apk):
    from androguard.core.dex import DEX
    with zipfile.ZipFile(apk) as a:
        require(a.testzip() is None,"ORIGINAL_ZIP_CRC")
        files=sorted(n for n in a.namelist()
          if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        require(files and files[0]=="classes.dex" and len(files)<=10,
                "BOUNDED_ORIGINAL_DEX_SET")
        for filename in files:
            d=DEX(a.read(filename))
            for cls in d.get_classes():
                owner=cls.get_name()
                if not owner.startswith(APP_PREFIX):continue
                for m in cls.get_methods():
                    if m.get_code() is None:continue
                    # Generator retains no original binary or DEX private
                    # values in the returned report.
                    yield owner,m.get_name(),(
                        (pc,i.get_name(),i.get_output())
                        for pc,i in m.get_instructions_idx())

def summarize(hits):
    modes={}
    for mode in ("MAIN","PROBE","CONFIG"):
        records=hits[mode]
        count=len(records)
        grouped=defaultdict(int)
        for x in records:grouped[x["owner_category"]]+=1
        modes[mode]={
            "direct_callsites":count,
            "caller_categories":dict(sorted(grouped.items())),
            "observation":("DIRECT_CALLSITE_PRESENT" if count else
                "NO_DIRECT_CALLSITE_OBSERVED_INDIRECT_DISPATCH_UNKNOWN"),
            "source_callsite_ids":[{"hash":x["caller_id_hash"],"pc":x["pc"]}
                for x in records[:20]],
        }
    return {
        "phase":"P198_FIXED_ORIGINAL_V138_CALLER_PROVENANCE_STATIC_ONLY",
        "exact_signed_v138_sha256":SIGNED_SHA,
        "targets":modes,
        "real_android_coroutine_invoked":False,
        "original_coroutine_os_generation_attested":False,
        "binder_receipt_delivered_to_original_coroutine":False,
        "host_unauthorized_process_spawn":"DENY",
        "production_node_http_ready":False,
        "release":"STRUCTURAL_BLOCKED"
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("original_signed_v138")
    parser.add_argument("--report",required=True)
    args=parser.parse_args()
    try:
        file=fixed_original(args.original_signed_v138)
        report=summarize(scan_stream(decoder_methods(file)))
        # A report holds only coarse category, method-hash, PC and count.
        pathlib.Path(args.report).write_text(json.dumps(report,indent=2)+"\n")
        print("P198_EXACT_SIGNED_V138_CALLER_GRAPH_DECODED=PASS")
        for mode in ("MAIN","PROBE","CONFIG"):
            row=report["targets"][mode]
            print("P198_"+mode+"_DIRECT_CALLSITE_COUNT="+str(row["direct_callsites"]))
            print("P198_"+mode+"_DISPATCH_EVIDENCE="+row["observation"])
        print("P198_REAL_ENGINE_COROUTINE_RUNTIME_ORIGIN=NOT_ATTESTED")
        print("P198_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED")
        print("P198_FORMAL_V139=STRUCTURAL_BLOCKED")
    except Block as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P198_DENY_ORIGINAL_DEX_DECODER_OR_FILE_ERROR",file=sys.stderr);sys.exit(2)
if __name__=="__main__":
    main()
