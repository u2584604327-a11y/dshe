#!/usr/bin/env python3
"""P209: original nodeIsUsable direct spawn vs P181 EngineManager-only gate.

Reads only SHA-pinned signed original and existing disposable Android35 build.
Does not patch/execute Node or access account/user files. Static callsite
parity never establishes runtime execution or process/UID ownership.
"""
import argparse
import hashlib
from pathlib import Path
import sys
import zipfile

from audit_signed_node_bootstrap import BOOT,SIGNED_SHA,need,normalize_descriptor,Denied
from audit_signed_node_locked import resolve_method
from audit_signed_node_delegate import safe_invoke_symbol,inspect_tries

ENGINE="Lcom/dsh/android/EngineManager;"
START_OWNER="Ljava/lang/ProcessBuilder;"
START_METHOD="start"
P47_GATE="Lcom/dsh/android/p47/P47LaunchGate;"

def original_method(dex,owner,name):
    matches=[m for c in dex.get_classes() if c.get_name()==owner
             for m in c.get_methods() if m.get_name()==name
             and m.get_code() is not None]
    need(len(matches)==1,"SINGLE_"+name+"_METHOD")
    return matches[0]

def direct_start_rows(rows):
    found=[]
    for pc,ins in rows:
        if not ins.get_name().startswith("invoke-"):
            continue
        symbol=safe_invoke_symbol(ins.get_output())
        if symbol==(START_OWNER,START_METHOD):
            found.append((pc,ins.get_name(),ins.get_length()))
    need(len(found)<=8,"DIRECT_SPAWN_COUNT_BOUND")
    return found

def check_spawn_coverage(original_rows,derived_rows,tries):
    """Fail closed if a startup call disappeared, multiplied or was relocated.

    The unprotected state is an alert, never an authorization.
    """
    orig=direct_start_rows(original_rows)
    derived=direct_start_rows(derived_rows)
    need(len(orig)==1,"SIGNED_USABILITY_EXACT_ONE_START")
    need(orig==derived,"DISPOSABLE_USABILITY_START_OPCODE_PC_DRIFT")
    pc,op,_=orig[0]
    need(op=="invoke-virtual","SIGNED_USABILITY_INVOKE_KIND_DRIFT")
    covered=[(start,end,targets,catch_all)
             for start,end,targets,catch_all in tries
             if start<=pc<end]
    need(len(covered)<=16,"SPAWN_HANDLER_COVERAGE_BOUND")
    return pc,covered

def verify_p181_scope(p181_source):
    """Verify source-level scope, not a proof of complete origin-wide mediation."""
    source=Path(p181_source)
    need(source.is_file() and not source.is_symlink(),"GATE_SOURCE_PRESENT")
    contents=source.read_text(encoding="utf-8")
    need("P181_THREE_ORIGINAL_START_DENY" in contents and
         "EngineManager.smali" in contents and
         '"probeBoot":' in contents and
         '"runDumpConfig":' in contents and
         "nodeIsUsable" not in contents,
         "P181_SOURCE_SCOPE_DRIFT")
    return True

def dex_from_zip(path,require_signed=False):
    from androguard.core.dex import DEX
    src=Path(path)
    need(src.is_file() and not src.is_symlink(),"APK_FILE")
    if require_signed:
        need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,
             "SIGNED_ORIGINAL_SHA256")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None,"APK_CRC")
        need("classes.dex" in z.namelist(),"PRIMARY_DEX_PRESENT")
        if require_signed:
            need("classes2.dex" in z.namelist(),"SIGNED_SECONDARY_DEX_PRESENT")
        else:
            need("classes3.dex" in z.namelist(),"P47_DERIVED_GATE_DEX_PRESENT")
        primary=DEX(z.read("classes.dex"))
        extras=DEX(z.read("classes3.dex")) if not require_signed else None
    return primary,extras

def audit(signed_apk,disposable_apk,p181_source):
    verify_p181_scope(p181_source)
    original,_=dex_from_zip(signed_apk,True)
    derived,gate_dex=dex_from_zip(disposable_apk,False)
    o=original_method(original,BOOT,"nodeIsUsable")
    d=original_method(derived,BOOT,"nodeIsUsable")
    need(normalize_descriptor(o.get_descriptor())==
         normalize_descriptor(d.get_descriptor()),"USABILITY_DESCRIPTOR_DRIFT")
    orows=list(o.get_instructions_idx())
    drows=list(d.get_instructions_idx())
    need(len(orows)==len(drows),"USABILITY_INSTRUCTION_COUNT_DRIFT")
    # Full untouched-method parity in byte PCs, opcodes and lengths. We
    # intentionally omit string literal values from logs.
    osig=[(pc,ins.get_name(),ins.get_length(),ins.get_output())
          for pc,ins in orows]
    dsig=[(pc,ins.get_name(),ins.get_length(),ins.get_output())
          for pc,ins in drows]
    need(osig==dsig,"USABILITY_FULL_INSTRUCTION_PARITY")
    tries=inspect_tries(o,orows)
    pc,covered=check_spawn_coverage(orows,drows,tries)
    gate_classes={c.get_name() for c in gate_dex.get_classes()}
    need(P47_GATE in gate_classes,"P47_TYPED_GATE_CLASS_MISSING")
    print("P209_NODE_USABILITY_SIGNED_V138_SHA_PINNED=PASS")
    print("P209_NODE_USABILITY_ORIGINAL_DERIVED_FULL_METHOD_PARITY=PASS")
    print("P209_NODE_USABILITY_DIRECT_START_PC="+str(pc))
    print("P209_NODE_USABILITY_ORIGINAL_DIRECT_START_COUNT=1")
    print("P209_NODE_USABILITY_DISPOSABLE_DIRECT_START_COUNT=1")
    print("P209_NODE_USABILITY_DIRECT_START_OPCODE=invoke-virtual")
    print("P209_NODE_USABILITY_ORIGINAL_TRY_RANGE_COUNT="+str(len(tries)))
    print("P209_NODE_USABILITY_START_PROTECTED_TRY_COUNT="+str(len(covered)))
    print("P209_NODE_USABILITY_START_CATCH_ALL_TRY_COUNT="+
          str(sum(1 for _,_,_,flag in covered if flag)))
    for start,end,targets,catch_all in covered:
        print("P209_NODE_USABILITY_START_COVERED_TRY_PC="+str(start)+
              "-"+str(end)+",CATCH_ALL="+("YES" if catch_all else "NO"))
    print("P209_NODE_USABILITY_P181_ENGINE_MANAGER_ONLY_SCOPE=PASS_STATIC")
    print("P209_NODE_USABILITY_P47_GATE_CLASS_PRESENT_IN_DISPOSABLE=YES")
    print("P209_NODE_USABILITY_DIRECT_START_NOT_REWRITTEN_BY_P181=YES")
    print("P209_NODE_USABILITY_DIRECT_SPAWN_RUNTIME_EXECUTED=NOT_ATTESTED")
    print("P209_NODE_USABILITY_TRY_RUNTIME_EXCEPTION=NOT_ATTESTED")
    print("P209_NODE_USABILITY_ORIGINAL_USER_PHONE_OR_DEX_CHANGED=NO")
    print("P209_NODE_USABILITY_NO_GLOBAL_SPAWN_MEDIATION=BLOCKED")
    print("P209_NODE_USABILITY_FORMAL_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P209_NODE_USABILITY_SIGNED_ORIGINAL_READONLY_AUDIT=PASS")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("signed_original_v138")
    ap.add_argument("disposable_derived_android35")
    ap.add_argument("--p181-source",
                    default="host_candidate/p47_no_fallback/p47_gate.py")
    args=ap.parse_args()
    try:audit(args.signed_original_v138,args.disposable_derived_android35,
              args.p181_source)
    except Denied as err:
        print(str(err),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P209_NODE_USABILITY_DENY_UNEXPECTED",file=sys.stderr);sys.exit(2)

if __name__=="__main__":main()
