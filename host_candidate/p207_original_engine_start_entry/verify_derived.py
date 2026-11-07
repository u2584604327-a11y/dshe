#!/usr/bin/env python3
"""P207 original vs disposable derived DEX EngineManager.start first-opcode parity."""
import argparse,sys,zipfile
from pathlib import Path
from androguard.core.dex import DEX
from patch_ci_only import verify_signed_original_start_signature
ENGINE="Lcom/dsh/android/EngineManager;"
ACTIVITY="Lcom/dsh/android/MainActivity;"
BOOT="Lcom/dsh/android/MainActivity$bootEngine$1;"
MARK="Lcom/dsh/android/p207/P207EngineStartEntryWitness;"
def need(v,reason):
    if not v:raise ValueError("P207_DENY_"+reason)
def get(dex,owner,name,desc):
    found=[m for c in dex.get_classes() if c.get_name()==owner
        for m in c.get_methods() if m.get_name()==name and
            "".join(m.get_descriptor().split())==desc]
    need(len(found)==1,"UNIQUE_METHOD_"+name)
    return found[0]
def ins(m):
    return [(x.get_name(),x.get_output()) for _,x in m.get_instructions_idx()]
def dex(path,name="classes.dex"):
    with zipfile.ZipFile(path) as z:return DEX(z.read(name))
def main():
    p=argparse.ArgumentParser()
    p.add_argument("original");p.add_argument("derived")
    a=p.parse_args()
    try:
        desc=verify_signed_original_start_signature(Path(a.original))
        old,new=dex(a.original),dex(a.derived)
        a1=ins(get(old,ENGINE,"start",desc))
        a2=ins(get(new,ENGINE,"start",desc))
        marks=[i for i,(op,out) in enumerate(a2)
               if op=="invoke-static" and MARK+"->mark()V" in out]
        need(marks==[0],"EXACT_FIRST_INVOKE_MARKER")
        need(a1==[val for i,val in enumerate(a2) if i!=marks[0]],
             "ORIGINAL_ENGINE_START_OPCODE_PARITY")
        for c in new.get_classes():
            for m in c.get_methods():
                if m.get_code() is None:continue
                if c.get_name()==ENGINE and m.get_name()=="start":continue
                for _,op in m.get_instructions_idx():
                    need(MARK+"->mark()V" not in op.get_output(),"MARKER_OUTSIDE_EXACT_METHOD")
        for owner,name,sig in [
           (ACTIVITY,"onCreate","(Landroid/os/Bundle;)V"),
           (ACTIVITY,"bootEngine","()V"),
           (BOOT,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")]:
            need(ins(get(old,owner,name,sig))==ins(get(new,owner,name,sig)),
                 "ORIGINAL_UPSTREAM_METHOD_CHANGED")
        witness=dex(a.derived,"classes3.dex")
        need(any(c.get_name()==MARK for c in witness.get_classes()),
             "DISPOSABLE_ONLY_JAVA_WITNESS_MISSING")
        print("P207_TEST_ONLY_ORIGINAL_ENGINE_START_ONLY_ONE_FIRST_INVOKE=PASS")
        print("P207_ENGINE_START_OTHER_ORIGINAL_INSTRUCTIONS=BYTECODE_SEMANTIC_PARITY")
        print("P207_ORIGINAL_ONCREATE_COMPLETE_INSTRUCTION_PARITY=PASS")
        print("P207_PC430_ORIGINAL_CALLSITE_UNCHANGED=PASS")
        print("P207_ORIGINAL_BOOT_AND_INVOKESUSPEND_PARITY=PASS")
        print("P207_ORIGINAL_OS_OWNER_P184_AND_NODE_READY=NOT_ATTESTED")
    except Exception:
        print("P207_DEX_PARITY_FAIL_CLOSED",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
