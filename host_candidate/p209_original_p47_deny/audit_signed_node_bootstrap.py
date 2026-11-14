#!/usr/bin/env python3
"""Read-only SHA-pinned signed-v138 TermuxBootstrap.installNodeRuntime DEX audit.

Never executes Node, inspects app credentials, modifies DEX or claims actual
Android coroutine suspension. Method strings/argv and device paths are NOT logged.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

SIGNED_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
START="Lcom/dsh/android/EngineManager$start$2;"
BOOT="Lcom/dsh/android/termux/TermuxBootstrap;"
PC_CALL=406
PC_RESULT=412
PC_GUARD=414
PC_EXIT=418

class Denied(Exception): pass
def need(value,tag):
    if not value: raise Denied("P209_NODE_BOOTSTRAP_DENY_"+tag)

def normalize_descriptor(text):
    return "".join(text.split())

def is_suspend_candidate(descriptor):
    """Syntactic Kotlin signature only; not evidence of runtime suspension."""
    return ("Lkotlin/coroutines/Continuation;" in descriptor and
            descriptor.endswith(")Ljava/lang/Object;"))

def node_call_classes(output):
    """Only conservative structural classes; do not emit raw strings/paths."""
    t=output
    labels=[]
    if "Lkotlin/coroutines/" in t or "Lkotlin/coroutines/intrinsics/" in t:
        labels.append("COROUTINE_API")
    if "Landroid/content/res/AssetManager;" in t or "->getAssets(" in t:
        labels.append("ASSET_API")
    if "Ljava/util/zip/" in t or "Ljava/util/jar/" in t:
        labels.append("ARCHIVE_API")
    if "Ljava/io/" in t or "Ljava/nio/file/" in t:
        labels.append("FILE_IO_API")
    if "Ljava/security/MessageDigest;" in t or "Ljavax/crypto/" in t:
        labels.append("HASH_OR_CRYPTO_API")
    if "Ljava/lang/ProcessBuilder;->start(" in t or "Ljava/lang/Runtime;->exec(" in t:
        labels.append("PROCESS_EXEC_API")
    if "Landroid/os/Build;" in t or "Ljava/lang/System;->getProperty(" in t:
        labels.append("ENVIRONMENT_API")
    return labels or ["OTHER_INVOKE"]

def bounded_method_summary(rows,try_count):
    need(1<=len(rows)<=12000,"METHOD_INSTRUCTION_BOUND")
    need(0<=try_count<=256,"TRY_REGION_BOUND")
    need(len({pc for pc,_ in rows})==len(rows),"UNIQUE_PC")
    returns=[]
    branches=[]
    counts=Counter()
    for pc,ins in rows:
        op=ins.get_name()
        if op.startswith("return"):returns.append((pc,op))
        if op.startswith("if-") or op.startswith("goto"):branches.append((pc,op))
        if op.startswith("invoke-"):
            for label in node_call_classes(ins.get_output()):
                counts[label]+=1
        if ("Landroid/os/Build;->SUPPORTED_ABIS" in ins.get_output()
                or "Landroid/os/Build;->CPU_ABI" in ins.get_output()):
            counts["ABI_FIELD_READ"]+=1
    need(len(returns)<=128 and len(branches)<=1024,"CONTROL_FLOW_BOUND")
    return returns,branches,counts

def callsite_shape(call_ins,result_ins,guard_ins,exit_ins,descriptor):
    need(call_ins.get_name()=="invoke-virtual","PC406_INVOKE_VIRTUAL_DRIFT")
    needle=BOOT+"->installNodeRuntime"+descriptor
    need(needle in normalize_descriptor(call_ins.get_output()),
         "PC406_CALLEE_DESCRIPTOR_MISMATCH")
    need(result_ins.get_name()=="move-result-object",
         "PC412_RESULT_DRIFT")
    need(guard_ins.get_name()=="if-ne","PC414_CONDITION_DRIFT")
    need(exit_ins.get_name()=="return-object","PC418_RETURN_DRIFT")
    # Only match the wire format, not actual DEX values or object identity.
    need(re.search(r"^\s*v10\b",result_ins.get_output()) is not None,
         "PC412_OUTPUT_REGISTER_DRIFT")
    need(re.match(r"\s*v10\s*,\s*v2\s*,",guard_ins.get_output()) is not None,
         "PC414_ARGUMENT_REGISTER_DRIFT")
    return True

def linked_delegate_names(rows):
    """A class name alone is insufficient: an original invoke must mention it."""
    expression=re.compile(
        r"(Lcom/dsh/android/termux/TermuxBootstrap\$installNodeRuntime\$[0-9]+;)")
    linked=set()
    for _,ins in rows:
        if not ins.get_name().startswith("invoke-"):
            continue
        match=expression.search(ins.get_output())
        if match:linked.add(match.group(1))
    need(len(linked)<=8,"BOUNDED_LINKED_LAMBDA_COUNT")
    return sorted(linked)

def inspect_linked_delegate_classes(dexes,wrapper_rows):
    """Only classes actually called by original wrapper; never infer runtime."""
    wanted=linked_delegate_names(wrapper_rows)
    found=[]
    for descriptor in wanted:
        instances=[(dex_name,cls)
                   for dex_name,dex in dexes
                   for cls in dex.get_classes()
                   if cls.get_name()==descriptor]
        need(len(instances)==1,"LINKED_LAMBDA_CLASS_UNIQUE")
        dex_name,cls=instances[0]
        methods=[m for m in cls.get_methods()
                 if m.get_name()=="invokeSuspend" and
                 normalize_descriptor(m.get_descriptor())==
                    "(Ljava/lang/Object;)Ljava/lang/Object;"]
        need(len(methods)==1 and methods[0].get_code() is not None,
             "LINKED_LAMBDA_INVOKESUSPEND_UNIQUE")
        method=methods[0]
        try_count=len(method.get_code().get_tries() or [])
        rets,branches,categories=bounded_method_summary(
            list(method.get_instructions_idx()),try_count)
        need(len(rets)>0,"LINKED_LAMBDA_MISSING_RETURN")
        found.append((descriptor,dex_name,rets,branches,categories,try_count))
    return wanted,found

def audit(apk):
    from androguard.core.dex import DEX
    source=Path(apk)
    need(source.is_file() and not source.is_symlink(),"PINNED_APK_REQUIRED")
    need(hashlib.sha256(source.read_bytes()).hexdigest()==SIGNED_SHA,
         "SIGNED_V138_SHA256")
    with zipfile.ZipFile(source) as z:
        need(z.testzip() is None,"SIGNED_ARCHIVE_CRC")
        names=sorted(x for x in z.namelist() if
                     re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",x))
        need(names==["classes.dex","classes2.dex"],"SIGNED_MULTIDEX_BOUND")
        dexes=[(name,DEX(z.read(name))) for name in names]
    bootstrap=[]
    start=[]
    for name,dex in dexes:
        for cls in dex.get_classes():
            cname=cls.get_name()
            if cname==BOOT:
                bootstrap.extend((name,m) for m in cls.get_methods()
                                 if m.get_name()=="installNodeRuntime")
            if cname==START:
                start.extend((name,m) for m in cls.get_methods()
                             if m.get_name()=="invokeSuspend"
                             and normalize_descriptor(m.get_descriptor())==
                                 "(Ljava/lang/Object;)Ljava/lang/Object;")
    need(len(start)==1 and start[0][0]=="classes.dex",
         "ORIGINAL_START2_UNIQUE_PRIMARY")
    need(len(bootstrap)==1,"BOOTSTRAP_METHOD_UNIQUE")
    dex_name,method=bootstrap[0]
    descriptor=normalize_descriptor(method.get_descriptor())
    need(len(descriptor)<=256 and descriptor.startswith("("),
         "BOOTSTRAP_DESCRIPTOR_BOUND")
    need(method.get_code() is not None,"BOOTSTRAP_METHOD_HAS_NO_CODE")
    start_rows=list(start[0][1].get_instructions_idx())
    bypc=dict(start_rows)
    need(all(pc in bypc for pc in (PC_CALL,PC_RESULT,PC_GUARD,PC_EXIT)),
         "PINNED_ORIGINAL_CALLSITE_PCS")
    need(bypc[PC_CALL].get_length()+PC_CALL==PC_RESULT,
         "ORIGINAL_INVOKE_RESULT_ADJACENCY")
    need(callsite_shape(bypc[PC_CALL],bypc[PC_RESULT],
                        bypc[PC_GUARD],bypc[PC_EXIT],descriptor),
         "CALLSITE_SHAPE")
    result_end=PC_RESULT+bypc[PC_RESULT].get_length()
    need(result_end==PC_GUARD and
         PC_GUARD+bypc[PC_GUARD].get_length()==PC_EXIT,
         "CALLSITE_CONTIGUOUS_406_418")
    code=method.get_code()
    try_items=code.get_tries() or []
    returns,branches,counts=bounded_method_summary(
        list(method.get_instructions_idx()),len(try_items))
    need(len(returns)>0,"BOOTSTRAP_NO_STATIC_RETURN")
    print("P209_NODE_BOOTSTRAP_SIGNED_SHA_PINNED=PASS")
    print("P209_NODE_BOOTSTRAP_METHOD_DEX="+dex_name)
    print("P209_NODE_BOOTSTRAP_METHOD_NAME=installNodeRuntime")
    print("P209_NODE_BOOTSTRAP_DESCRIPTOR="+descriptor)
    print("P209_NODE_BOOTSTRAP_KOTLIN_SUSPEND_SIGNATURE="+
          ("SYNTACTIC_CANDIDATE" if is_suspend_candidate(descriptor)
           else "NOT_PROVEN_BY_DESCRIPTOR"))
    print("P209_NODE_BOOTSTRAP_PC406_CALL_DESCRIPTOR_MATCH=PASS")
    print("P209_NODE_BOOTSTRAP_PC412_RESULT_PC414_GUARD_PC418_RETURN=PASS")
    print("P209_NODE_BOOTSTRAP_METHOD_RETURN_COUNT="+str(len(returns)))
    print("P209_NODE_BOOTSTRAP_METHOD_CONDITIONAL_GOTO_COUNT="+str(len(branches)))
    print("P209_NODE_BOOTSTRAP_METHOD_TRY_RANGE_COUNT="+str(len(try_items)))
    for op,n in sorted(Counter(op for _,op in returns).items()):
        print("P209_NODE_BOOTSTRAP_RETURN_OPCODE="+op+",COUNT="+str(n))
    for label in ("COROUTINE_API","ASSET_API","ARCHIVE_API","FILE_IO_API",
                  "HASH_OR_CRYPTO_API","PROCESS_EXEC_API","ENVIRONMENT_API",
                  "ABI_FIELD_READ","OTHER_INVOKE"):
        print("P209_NODE_BOOTSTRAP_STATIC_CALL_CATEGORY_"+label+"="+
              str(counts.get(label,0)))
    wanted,delegates=inspect_linked_delegate_classes(
        dexes,list(method.get_instructions_idx()))
    print("P209_NODE_BOOTSTRAP_DIRECT_LINKED_LAMBDA_COUNT="+str(len(wanted)))
    for index,(descriptor,dex_file,rets,branches,categories,tries) in enumerate(delegates,1):
        safe=descriptor.removeprefix("Lcom/dsh/android/termux/").removesuffix(";")
        print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_CLASS="+safe)
        print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_DEX="+dex_file)
        print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_RETURN_COUNT="+str(len(rets)))
        print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_BRANCH_COUNT="+str(len(branches)))
        print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_TRY_COUNT="+str(tries))
        for kind in ("COROUTINE_API","ASSET_API","ARCHIVE_API","FILE_IO_API",
                     "HASH_OR_CRYPTO_API","PROCESS_EXEC_API",
                     "ENVIRONMENT_API","ABI_FIELD_READ","OTHER_INVOKE"):
            print("P209_NODE_LINKED_LAMBDA_"+str(index)+"_CALL_CATEGORY_"+
                  kind+"="+str(categories.get(kind,0)))
    print("P209_NODE_BOOTSTRAP_LINKED_LAMBDA_VERIFICATION="+
          ("READONLY_BOUNDED_PASS" if delegates else "NO_LINKED_LAMBDA_AT_THIS_DEPTH"))
    print("P209_NODE_LINKED_LAMBDA_TRANSITIVE_CALLEES=NOT_AUDITED")
    print("P209_NODE_BOOTSTRAP_DIRECT_CALLS_NOT_TRANSITIVE=YES")
    print("P209_NODE_BOOTSTRAP_RETURN_VALUE_SEMANTICS=NOT_ATTESTED")
    print("P209_NODE_BOOTSTRAP_RUNTIME_SUSPENSION_OR_EXCEPTION=NOT_ATTESTED")
    print("P209_NODE_BOOTSTRAP_OFFLINE_ASSET_INTEGRITY_AND_ABI=NOT_ATTESTED")
    print("P209_NODE_BOOTSTRAP_BROWSER_OWNER_AND_P47=NOT_WIRED")
    print("P209_NODE_BOOTSTRAP_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P209_NODE_BOOTSTRAP_ORIGINAL_DEX_READONLY_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    args=p.parse_args()
    try:audit(args.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_NODE_BOOTSTRAP_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
