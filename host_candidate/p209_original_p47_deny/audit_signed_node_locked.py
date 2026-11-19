#!/usr/bin/env python3
"""P209 signed-v138 PC130 -> TermuxBootstrap installer original-call trace.

Strict SHA-pinned original DEX only. No modified Android APK inspection,
code execution, account files, argument strings, tokens or real paths output.
This is original static invocation identity, not runtime reachability.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import (
    SIGNED_SHA,BOOT,normalize_descriptor,need,bounded_method_summary,
    node_call_classes,linked_delegate_names,Denied,
)
from audit_signed_node_delegate import static_call_inventory

DELEGATE="Lcom/dsh/android/termux/TermuxBootstrap$installNodeRuntime$2;"
DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
ACCESSOR="access$installNodeRuntimeLocked"
LOCKED="installNodeRuntimeLocked"

def resolve_method(dexes,owner,name,description=None):
    """Only a unique *signed original* method qualifies; do not guess overloads."""
    found=[(n,m) for n,dex in dexes
           for cls in dex.get_classes() if cls.get_name()==owner
           for m in cls.get_methods() if m.get_name()==name and
           (description is None or
            normalize_descriptor(m.get_descriptor())==description)]
    need(len(found)==1 and found[0][1].get_code() is not None,
         "METHOD_IDENTITY_UNIQUE_"+name.replace("$","_"))
    return found[0]

def exact_original_call(rows,owner,name,descriptor):
    """Return unique actual DEX invoke PC whose target has exact descriptor."""
    target=owner+"->"+name+descriptor
    matches=[(pc,inst) for pc,inst in rows if
             inst.get_name().startswith("invoke-") and
             target in normalize_descriptor(inst.get_output())]
    need(len(matches)==1,"EXACT_ONE_SOURCE_INVOKE_"+name.replace("$","_"))
    return matches[0]

def static_method_stats(method):
    code=method.get_code()
    need(code is not None,"NO_METHOD_CODE")
    rows=list(method.get_instructions_idx())
    attempts=len(code.get_tries() or [])
    returns,branches,categories=bounded_method_summary(rows,attempts)
    calls=static_call_inventory(rows)
    io=[(pc,kind,methodname) for pc,t,kind,methodname in calls if t=="IO"]
    helpers=[(pc,methodname) for pc,t,_,methodname in calls if t=="TERMUX_HELPER"]
    return rows,attempts,returns,branches,categories,io,helpers

def inspect_signed(apk):
    from androguard.core.dex import DEX
    source=Path(apk)
    need(source.is_file() and not source.is_symlink(),"ORIGINAL_APK_REQUIRED")
    need(hashlib.sha256(source.read_bytes()).hexdigest()==SIGNED_SHA,
         "ORIGINAL_V138_SHA256")
    with zipfile.ZipFile(source) as z:
        need(z.testzip() is None,"SIGNED_ZIP_CRC")
        names=sorted(n for n in z.namelist() if
                     re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(names==["classes.dex","classes2.dex"],"SIGNED_DEX_SET")
        dexes=[(name,DEX(z.read(name))) for name in names]
    wrapper_dex,wrapper=resolve_method(dexes,BOOT,"installNodeRuntime")
    need(wrapper_dex=="classes.dex","WRAPPER_PRIMARY_DEX")
    links=linked_delegate_names(list(wrapper.get_instructions_idx()))
    need(links==[DELEGATE],"LINKED_DELEGATE_NOT_EXACT")
    delegate_dex,delegate=resolve_method(dexes,DELEGATE,"invokeSuspend",DESC)
    need(delegate_dex=="classes.dex","DELEGATE_PRIMARY_DEX")
    accessor_dex,accessor=resolve_method(dexes,BOOT,ACCESSOR)
    need(accessor_dex=="classes.dex","ACCESSOR_PRIMARY_DEX")
    delegate_rows=list(delegate.get_instructions_idx())
    pc,inst=exact_original_call(delegate_rows,BOOT,ACCESSOR,
                                normalize_descriptor(accessor.get_descriptor()))
    need(pc==130,"DELEGATE_ACCESSOR_PC130_DRIFT")
    accessor_rows=list(accessor.get_instructions_idx())
    locked_dex,locked=resolve_method(dexes,BOOT,LOCKED)
    need(locked_dex=="classes.dex","LOCKED_BODY_PRIMARY_DEX")
    pc2,inst2=exact_original_call(accessor_rows,BOOT,LOCKED,
                                  normalize_descriptor(locked.get_descriptor()))
    ar,atry,aret,abr,acat,aio,ahelpers=static_method_stats(accessor)
    lr,ltry,lret,lbr,lcat,lio,lhelpers=static_method_stats(locked)
    need(len(aret)>=1 and len(lret)>=1,"WRAPPER_OR_LOCKED_NO_RETURN")
    print("P209_NODE_LOCKED_ORIGINAL_SIGNED_SHA_PINNED=PASS")
    print("P209_NODE_LOCKED_WRAPPER_TO_DELEGATE_EXACT_LINK=PASS")
    print("P209_NODE_LOCKED_DELEGATE_ACCESSOR_PC=130")
    print("P209_NODE_LOCKED_ACCESSOR_INVOKE_OP="+inst.get_name())
    print("P209_NODE_LOCKED_ACCESSOR_TO_LOCKED_PC="+str(pc2))
    print("P209_NODE_LOCKED_ACCESSOR_TO_LOCKED_OP="+inst2.get_name())
    print("P209_NODE_LOCKED_ACCESSOR_STATIC_RETURN_COUNT="+str(len(aret)))
    print("P209_NODE_LOCKED_ACCESSOR_STATIC_TRY_COUNT="+str(atry))
    print("P209_NODE_LOCKED_BODY_STATIC_INSTRUCTION_COUNT="+str(len(lr)))
    print("P209_NODE_LOCKED_BODY_STATIC_RETURN_COUNT="+str(len(lret)))
    print("P209_NODE_LOCKED_BODY_STATIC_BRANCH_COUNT="+str(len(lbr)))
    print("P209_NODE_LOCKED_BODY_STATIC_TRY_COUNT="+str(ltry))
    print("P209_NODE_LOCKED_BODY_DIRECT_IO_OWNER_CALL_COUNT="+str(len(lio)))
    print("P209_NODE_LOCKED_BODY_DIRECT_TERMUX_HELPER_COUNT="+str(len(lhelpers)))
    for p,kind,name in lio[:64]:
        print("P209_NODE_LOCKED_BODY_DIRECT_IO_PC="+str(p)+",KIND="+kind+
              ",METHOD="+name)
    for p,name in lhelpers[:64]:
        print("P209_NODE_LOCKED_BODY_DIRECT_HELPER_PC="+str(p)+",METHOD="+name)
    for category in ("COROUTINE_API","ASSET_API","ARCHIVE_API","FILE_IO_API",
                     "HASH_OR_CRYPTO_API","PROCESS_EXEC_API",
                     "ENVIRONMENT_API","ABI_FIELD_READ","OTHER_INVOKE"):
        print("P209_NODE_LOCKED_BODY_BROAD_CALL_CATEGORY_"+category+"="+
              str(lcat.get(category,0)))
    print("P209_NODE_LOCKED_REAL_ANDROID_EXECUTION=NOT_ATTESTED")
    print("P209_NODE_LOCKED_ASSET_ABI_HASH_INTEGRITY=NOT_ATTESTED")
    print("P209_NODE_LOCKED_EXCEPTION_HANDLER_EXECUTION=NOT_ATTESTED")
    print("P209_NODE_LOCKED_CHILD_PROCESS_OWNER=NOT_ATTESTED")
    print("P209_NODE_LOCKED_ORIGINAL_DEX_MODIFIED=NO")
    print("P209_NODE_LOCKED_V139=STRUCTURAL_BLOCKED")
    print("P209_NODE_LOCKED_SIGNED_ORIGINAL_CALL_TRACE=PASS")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("signed_original_v138")
    args=parser.parse_args()
    try:inspect_signed(args.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_NODE_LOCKED_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
