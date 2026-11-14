#!/usr/bin/env python3
"""P209 signed v138 linked Node installer coroutine: bounded, read-only audit.

Original SHA-pinned APK only. Exact original callsite links the nested class.
No user paths, arguments, passwords, string constants or filesystem reads
outside the signed APK are printed. No runtime branch or install is attested.
All DEX code-unit addresses are explicitly converted to byte PCs.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import (
    SIGNED_SHA, BOOT, START, Denied, need, normalize_descriptor,
    linked_delegate_names, bounded_method_summary,
)

DELEGATE="Lcom/dsh/android/termux/TermuxBootstrap$installNodeRuntime$2;"
DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
INVOKE=re.compile(r"(L[A-Za-z0-9_/$]{1,160};)->([A-Za-z0-9_$<>]{1,90})\(")
ALLOWED_IO_OWNERS={
    "java.io.File":"FILE_METADATA",
    "java.io.FileInputStream":"INPUT_STREAM",
    "java.io.FileOutputStream":"OUTPUT_STREAM",
    "java.io.InputStream":"INPUT_STREAM",
    "java.io.OutputStream":"OUTPUT_STREAM",
    "java.io.BufferedInputStream":"INPUT_STREAM",
    "java.io.BufferedOutputStream":"OUTPUT_STREAM",
    "java.io.FilterInputStream":"INPUT_STREAM",
    "java.io.FilterOutputStream":"OUTPUT_STREAM",
    "java.io.RandomAccessFile":"FILE_RANDOM_ACCESS",
    "java.nio.file.Files":"NIO_FILES",
    "java.nio.file.Path":"NIO_PATH",
}
SENSITIVE_FORBIDDEN=("password","token","secret","cookie","authorization",
                     "account","email","apikey","accesskey")

def safe_invoke_symbol(out):
    """Method identity only; intentionally omit operand values and descriptor."""
    match=INVOKE.search(out)
    if match is None:return None
    owner,name=match.groups()
    if any(w in name.lower() for w in SENSITIVE_FORBIDDEN):
        return ("REDACTED_OWNER","REDACTED_METHOD")
    return owner,name

def io_class(owner):
    if owner is None:return "UNRESOLVED"
    dotted=owner.strip("L;").replace("/",".")
    return ALLOWED_IO_OWNERS.get(dotted,"OTHER_IO_OWNER")

def legacy_io_signature_mentions(rows):
    """Historical broad category: I/O may appear in descriptor, not callee."""
    return sum(1 for _,ins in rows if
               ins.get_name().startswith("invoke-") and
               ("Ljava/io/" in ins.get_output() or
                "Ljava/nio/file/" in ins.get_output()))

def static_call_inventory(rows):
    """Returns bounded, sanitized static locations; never arbitrary strings."""
    calls=[]
    for pc,ins in rows:
        if not ins.get_name().startswith("invoke-"):continue
        target=safe_invoke_symbol(ins.get_output())
        owner,method=target if target else (None,None)
        if owner and (owner.startswith("Ljava/io/") or
                      owner.startswith("Ljava/nio/file/")):
            calls.append((pc,"IO",io_class(owner),method if method and
                          re.fullmatch(r"[A-Za-z0-9_$<>]{1,90}",method)
                          else "UNKNOWN"))
        elif owner and owner.startswith("Lcom/dsh/android/termux/"):
            calls.append((pc,"TERMUX_HELPER","ORIGINAL_APP",
                          method if re.fullmatch(r"[A-Za-z0-9_$<>]{1,90}",method)
                          else "UNKNOWN"))
        elif owner and ("Lkotlin/coroutines/" in owner or
                        "Lkotlinx/coroutines/" in owner):
            calls.append((pc,"COROUTINE","LIBRARY","METHOD_NOT_LOGGED"))
        elif owner and ("Ljava/security/" in owner or
                        "Landroid/os/Build;" in owner):
            calls.append((pc,"RUNTIME_ENV","LIBRARY","METHOD_NOT_LOGGED"))
        else:
            calls.append((pc,"OTHER","NOT_CLASSIFIED","METHOD_NOT_LOGGED"))
    need(len(calls)<=256,"STATIC_CALL_INVENTORY_BOUND")
    return calls

def inspect_tries(method,rows):
    """Associate try_items with exact catch targets; no runtime proof.

    get_start_addr/count and handler.get_addr are DEX 16-bit code units.
    get_handler_off is a BYTE OFFSET into encoded handler-list payload.
    """
    code=method.get_code()
    items=code.get_tries() or []
    need(1<=len(items)<=64,"TRY_COUNT_BOUND")
    all_pc={pc for pc,_ in rows}
    limit=rows[-1][0]+rows[-1][1].get_length()
    need(limit<=131072,"METHOD_BYTE_LENGTH_BOUND")
    handlers=code.get_handlers()
    need(handlers is not None,"MISSING_HANDLER_LIST")
    encoded=handlers.get_list() or []
    need(1<=len(encoded)<=64,"HANDLER_LIST_BOUND")
    handler_by_off={h.get_off():h for h in encoded}
    need(len(handler_by_off)==len(encoded),"DUPLICATE_HANDLER_OFFSET")
    info=[]
    for item in items:
        start=item.get_start_addr()*2
        end=start+item.get_insn_count()*2
        off=item.get_handler_off()+handlers.get_off()
        need(start in all_pc and
             (end in all_pc or end==limit) and
             0<=start<end<=limit,"TRY_RANGE_BOUNDARY")
        need(off in handler_by_off,"TRY_HANDLER_REF_NOT_RESOLVED")
        h=handler_by_off[off]
        pairs=h.get_handlers() or []
        targets=[]
        for pair in pairs:
            target=pair.get_addr()*2
            need(target in all_pc,"CATCH_TARGET_NOT_IN_CODE")
            targets.append(target)
        catch_all=h.get_size()<=0
        if catch_all:
            target=h.get_catch_all_addr()*2
            need(target in all_pc,"CATCH_ALL_TARGET_NOT_IN_CODE")
            targets.append(target)
        need(1<=len(targets)<=32,"EMPTY_OR_UNBOUNDED_HANDLER")
        need(len(set(targets))==len(targets),"DUPLICATE_CATCH_DESTINATION")
        info.append((start,end,len(targets),catch_all))
    need(len(info)==len(items),"TRY_INVENTORY_MISMATCH")
    return info

def inspect_signed(apk):
    from androguard.core.dex import DEX
    src=Path(apk)
    need(src.is_file() and not src.is_symlink(),"SIGNED_APK_FILE")
    need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,"SIGNED_SHA256")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None,"SIGNED_ZIP_CRC")
        names=sorted(n for n in z.namelist()
                     if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(names==["classes.dex","classes2.dex"],"SIGNED_TWO_DEX")
        dexes=[(n,DEX(z.read(n))) for n in names]
    wrappers=[]
    delegates=[]
    for dex_name,dex in dexes:
        for cls in dex.get_classes():
            if cls.get_name()==BOOT:
                wrappers.extend((dex_name,m) for m in cls.get_methods()
                                if m.get_name()=="installNodeRuntime")
            if cls.get_name()==DELEGATE:
                delegates.extend((dex_name,m) for m in cls.get_methods()
                                 if m.get_name()=="invokeSuspend" and
                                 normalize_descriptor(m.get_descriptor())==DESC)
    need(len(wrappers)==1 and wrappers[0][0]=="classes.dex" and
         wrappers[0][1].get_code() is not None,"UNIQUE_WRAPPER_PRIMARY")
    linked=linked_delegate_names(list(wrappers[0][1].get_instructions_idx()))
    need(linked==[DELEGATE],"WRAPPER_LINKED_DELEGATE_NOT_EXACT")
    need(len(delegates)==1 and delegates[0][0]=="classes.dex" and
         delegates[0][1].get_code() is not None,"UNIQUE_INVOKESUSPEND_PRIMARY")
    m=delegates[0][1]
    rows=list(m.get_instructions_idx())
    calls=static_call_inventory(rows)
    io=[x for x in calls if x[1]=="IO"]
    helpers=[x for x in calls if x[1]=="TERMUX_HELPER"]
    legacy_mentions=legacy_io_signature_mentions(rows)
    # Previous audit counted every invoke whose complete descriptor mentioned
    # java.io/nio. It did NOT establish the invoked class was an IO class.
    need(legacy_mentions==8,"SIGNED_BROAD_IO_MENTION_BASELINE_DRIFT")
    need(len(io)<=legacy_mentions,"DIRECT_IO_CALLEE_COUNT_EXCEEDS_MENTIONS")
    tries=inspect_tries(m,rows)
    returns,branches,_=bounded_method_summary(rows,len(tries))
    need(len(returns)==1 and len(branches)==4,"SIGNED_DELEGATE_SHAPE_DRIFT")
    print("P209_NODE_DELEGATE_SHA_PINNED=PASS")
    print("P209_NODE_DELEGATE_BROAD_IO_SIGNATURE_MENTION_COUNT="+str(legacy_mentions))
    print("P209_NODE_DELEGATE_BROAD_IO_MENTIONS_NOT_DIRECT_CALLEES="+
          str(legacy_mentions-len(io)))
    print("P209_NODE_DELEGATE_ORIGINAL_WRAPPER_INVOKE_LINK=PASS")
    print("P209_NODE_DELEGATE_METHOD=TermuxBootstrap$installNodeRuntime$2.invokeSuspend")
    print("P209_NODE_DELEGATE_DIRECT_IO_CALL_COUNT="+str(len(io)))
    for pc,_,kind,method in io:
        print("P209_NODE_DELEGATE_IO_PC="+str(pc)+",KIND="+kind+
              ",METHOD="+method)
    print("P209_NODE_DELEGATE_DIRECT_TERMUX_HELPER_COUNT="+str(len(helpers)))
    for pc,_,kind,method in helpers[:32]:
        print("P209_NODE_DELEGATE_HELPER_PC="+str(pc)+",METHOD="+method)
    print("P209_NODE_DELEGATE_TRY_RANGE_COUNT="+str(len(tries)))
    for i,(start,end,target_count,catch_all) in enumerate(tries,1):
        print("P209_NODE_DELEGATE_TRY_"+str(i)+"_START_PC="+str(start))
        print("P209_NODE_DELEGATE_TRY_"+str(i)+"_END_PC_EXCLUSIVE="+str(end))
        print("P209_NODE_DELEGATE_TRY_"+str(i)+"_TARGET_COUNT="+str(target_count))
        print("P209_NODE_DELEGATE_TRY_"+str(i)+"_CATCH_ALL="+
              ("YES" if catch_all else "NO"))
    print("P209_NODE_DELEGATE_RETURN_COUNT="+str(len(returns)))
    for pc,op in returns:
        print("P209_NODE_DELEGATE_RETURN_PC="+str(pc)+",OP="+op)
    print("P209_NODE_DELEGATE_BRANCH_COUNT="+str(len(branches)))
    for pc,op in branches:
        print("P209_NODE_DELEGATE_BRANCH_PC="+str(pc)+",OP="+op)
    print("P209_NODE_DELEGATE_HANDLER_PC_NORMAL_CFG_EXECUTED=NOT_ATTESTED")
    print("P209_NODE_DELEGATE_TRY_RANGES_RUNTIME_EXCEPTIONS=NOT_ATTESTED")
    print("P209_NODE_DELEGATE_OFFLINE_NODE_ASSETS_ABI_CHECKSUM=NOT_ATTESTED")
    print("P209_NODE_DELEGATE_RETURN_OR_SUSPENSION=NOT_ATTESTED")
    print("P209_NODE_DELEGATE_TRANSITIVE_HELPERS=NOT_AUDITED")
    print("P209_NODE_DELEGATE_ORIGINAL_ANDROID_ENTRY=NOT_ATTESTED")
    print("P209_NODE_DELEGATE_ORIGINAL_DEX_MUTATED=NO")
    print("P209_NODE_DELEGATE_RELEASE=STRUCTURAL_BLOCKED")
    print("P209_NODE_DELEGATE_SIGNED_STATIC_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    args=p.parse_args()
    try:inspect_signed(args.signed_original_v138)
    except Denied as err:
        print(str(err),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_NODE_DELEGATE_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
