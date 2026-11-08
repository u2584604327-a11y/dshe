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
MAIN_ACTIVITY_OWNER="Lcom/dsh/android/MainActivity;"
UPSTREAM_BOOT_NAMES=frozenset(("bootEngine","access$bootEngine"))
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

# Classification is purely syntactic, never proof of an actual user gesture.
LIFECYCLE_CALLBACKS=frozenset(("onCreate","onStart","onResume","onRestart",
  "onNewIntent","onActivityResult","onRequestPermissionsResult",
  "onServiceConnected","onBind","onHandleIntent","onReceive"))
UI_CALLBACKS=frozenset(("onClick","onLongClick","onItemClick",
  "onItemLongClick","onOptionsItemSelected","onContextItemSelected",
  "onMenuItemClick","onNavigationItemSelected","onPreferenceClick","onTouch"))

def source_entry_kind(owner,name):
    if name=="invokeSuspend":return "COROUTINE_CONTINUATION"
    if name in LIFECYCLE_CALLBACKS:return "LIFECYCLE_NAMED_METHOD"
    if name in UI_CALLBACKS:return "UI_CALLBACK_NAMED_METHOD"
    if name in ("<init>","<clinit>"):return "CLASS_INITIALIZATION"
    if name in ("invoke","invoke$default"):
        return "KOTLIN_INVOKE_AMBIGUOUS"
    if name.startswith("lambda$") or "$lambda$" in name:
        return "GENERATED_LAMBDA_AMBIGUOUS"
    return "OTHER_METHOD_NO_UI_PROOF"

def start_owner_family(owner):
    # Explicitly match only the known original activity family; no private
    # method/class names, arguments, or DEX strings enter results.
    if owner.startswith("Lcom/dsh/android/MainActivity$bootEngine$"):
        return "MAIN_BOOT_ENGINE_COROUTINE_FAMILY"
    if owner.startswith("Lcom/dsh/android/MainActivity$"):
        return "OTHER_MAIN_ACTIVITY_NESTED_FAMILY"
    if owner==MAIN_ACTIVITY_OWNER:return "MAIN_ACTIVITY_DIRECT"
    return "OTHER_OR_UNCLASSIFIED_FAMILY"

def scan_upstream_boot_methods(methods):
    """Read-only exact invocations of MainActivity.bootEngine or its accessor.
    This does NOT prove caller dispatch, user consent, or complete call chains.
    """
    rows=[]
    seen_methods=0
    for owner,name,instructions in methods:
        seen_methods+=1
        require(seen_methods<=MAX_METHODS,"UPSTREAM_METHOD_BOUND")
        invokes=0
        for pc,op,operand in instructions:
            if not op.startswith("invoke-"):continue
            invokes+=1
            require(invokes<=MAX_CALLS_PER_METHOD,"UPSTREAM_INVOKES_BOUND")
            match=INVOKE_REF.search(operand)
            if not match:continue
            callee,callee_method,_=match.groups()
            if callee!=MAIN_ACTIVITY_OWNER or callee_method not in UPSTREAM_BOOT_NAMES:
                continue
            rows.append({"owner_category":callable_category(owner),
                         "source_entry_kind":source_entry_kind(owner,name),
                         "caller_family":start_owner_family(owner)})
            require(len(rows)<=MAX_HITS,"UPSTREAM_CALLSITE_BOUND")
    return rows

def summarize_upstream(rows):
    kind_counts=defaultdict(int)
    owner_counts=defaultdict(int)
    for row in rows:
        kind_counts[row["source_entry_kind"]]+=1
        owner_counts[row["owner_category"]+"__"+row["source_entry_kind"]]+=1
    return {"boot_method_direct_callsites":len(rows),
            "named_callback_kinds":dict(sorted(kind_counts.items())),
            "source_owner_kind_matrix":dict(sorted(owner_counts.items())),
            "user_event_runtime_proven":False,
            "boot_engine_executed":False}

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
                    "source_entry_kind":source_entry_kind(owner,name),
                    "caller_family":start_owner_family(owner),
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
        kinds=defaultdict(int)
        owner_kinds=defaultdict(int)
        owner_families=defaultdict(int)
        for x in records:
            grouped[x["owner_category"]]+=1
            kinds[x["source_entry_kind"]]+=1
            owner_kinds[x["owner_category"]+"__"+x["source_entry_kind"]]+=1
            owner_families[x["caller_family"]]+=1
        modes[mode]={
            "direct_callsites":count,
            "caller_categories":dict(sorted(grouped.items())),
            "source_entry_kinds":dict(sorted(kinds.items())),
            "owner_entry_matrix":dict(sorted(owner_kinds.items())),
            "owner_family_counts":dict(sorted(owner_families.items())),
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
        "genuine_user_action_trigger_attested":False,
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
        report["upstream_boot"]=summarize_upstream(
            scan_upstream_boot_methods(decoder_methods(file)))
        # No original method/class strings, credentials, tokens or operands are logged.
        pathlib.Path(args.report).write_text(json.dumps(report,indent=2)+"\n")
        print("P198_EXACT_SIGNED_V138_CALLER_GRAPH_DECODED=PASS")
        for mode in ("MAIN","PROBE","CONFIG"):
            row=report["targets"][mode]
            print("P198_"+mode+"_DIRECT_CALLSITE_COUNT="+str(row["direct_callsites"]))
            print("P198_"+mode+"_DISPATCH_EVIDENCE="+row["observation"])
            if mode=="MAIN":
                for kind,count in sorted(row["source_entry_kinds"].items()):
                    print("P198_MAIN_KIND_"+kind+"="+str(count))
                for kind,count in sorted(row["owner_entry_matrix"].items()):
                    print("P198_MAIN_OWNER_KIND_"+kind+"="+str(count))
                for family,count in sorted(row["owner_family_counts"].items()):
                    print("P198_MAIN_OWNER_FAMILY_"+family+"="+str(count))
        upstream=report["upstream_boot"]
        print("P198_UPSTREAM_BOOT_DIRECT_CALLSITE_COUNT="+
              str(upstream["boot_method_direct_callsites"]))
        for kind,count in sorted(upstream["named_callback_kinds"].items()):
            print("P198_UPSTREAM_BOOT_METHOD_KIND_"+kind+"="+str(count))
        for kind,count in sorted(upstream["source_owner_kind_matrix"].items()):
            print("P198_UPSTREAM_BOOT_OWNER_KIND_"+kind+"="+str(count))
        print("P198_REAL_UI_TRIGGER=NOT_ATTESTED")
        print("P198_REAL_ENGINE_COROUTINE_RUNTIME_ORIGIN=NOT_ATTESTED")
        print("P198_ORIGINAL_ARM64_NODE_HTTP_TOKEN_READY=NOT_WIRED")
        print("P198_FORMAL_V139=STRUCTURAL_BLOCKED")
    except Block as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P198_DENY_ORIGINAL_DEX_DECODER_OR_FILE_ERROR",file=sys.stderr);sys.exit(2)
if __name__=="__main__":
    main()
