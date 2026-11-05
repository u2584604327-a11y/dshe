#!/usr/bin/env python3
"""P208 compare original real start$2 coroutine vs disposable first marker + frozen P40 DENY redirect."""
import argparse,sys,zipfile
from pathlib import Path
from androguard.core.dex import DEX
from patch_ci_only import verify_signed_original_coroutine
ENGINE="Lcom/dsh/android/EngineManager;"
START2="Lcom/dsh/android/EngineManager$start$2;"
ACTIVITY="Lcom/dsh/android/MainActivity;"
BOOT="Lcom/dsh/android/MainActivity$bootEngine$1;"
WITNESS="Lcom/dsh/android/p208/P208StartCoroutineWitness;"
OLD="Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
NEW="Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
class Denied(Exception):pass
def require(ok,code):
    if not ok:raise Denied("P208_DENY_"+code)
def load(path,name="classes.dex"):
    with zipfile.ZipFile(path) as z:return DEX(z.read(name))
def find(dex,owner,name,desc):
    arr=[m for c in dex.get_classes() if c.get_name()==owner
       for m in c.get_methods() if m.get_name()==name and
       "".join(m.get_descriptor().split())==desc]
    require(len(arr)==1,"EXACT_"+name)
    return arr[0]
def instr(m):
    return [(pc,i.get_name(),i.get_output()) for pc,i in m.get_instructions_idx()]
def compare(orig,derived):
    first=instr(orig)
    second=instr(derived)
    marked=[i for i,(pc,op,out) in enumerate(second) if
            op=="invoke-static" and WITNESS+"->mark()V" in out]
    require(marked==[0],"EXACT_SINGLE_FIRST_MARKER")
    second=[value for i,value in enumerate(second) if i!=marked[0]]
    require(len(first)==len(second),"EXACT_ORIGINAL_COUNT_EXCEPT_ONE_MARKER")
    rewritten=[]
    for idx,(a,b) in enumerate(zip(first,second)):
        ap,ao,at=a;bp,bo,bt=b
        if ao==bo and at==bt:continue
        if (ap==3912 and ao=="invoke-virtual" and bo=="invoke-static" and
            at.endswith(OLD) and bt.endswith(NEW) and
            at[:-len(OLD)]==bt[:-len(NEW)]):
            rewritten.append(ap);continue
        require(False,"UNAUTHORIZED_ORIGINAL_INSTRUCTION_CHANGE_INDEX_"+str(idx))
    require(rewritten==[3912],"ONLY_FROZEN_P40_DENY_REDIRECT")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("original");p.add_argument("derived")
    a=p.parse_args()
    try:
        verify_signed_original_coroutine(Path(a.original))
        o,d=load(a.original),load(a.derived)
        compare(find(o,START2,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;"),
                find(d,START2,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;"))
        for c in d.get_classes():
            for m in c.get_methods():
                if m.get_code() is None:continue
                if c.get_name()==START2 and m.get_name()=="invokeSuspend":continue
                for _,i in m.get_instructions_idx():
                    require(WITNESS+"->mark()V" not in i.get_output(),"UNEXPECTED_MARKER_LOCATION")
        for owner,name,desc in [
            (ENGINE,"start","(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"),
            (ACTIVITY,"onCreate","(Landroid/os/Bundle;)V"),
            (ACTIVITY,"bootEngine","()V"),
            (BOOT,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")]:
            a1=[(op,out) for _,op,out in instr(find(o,owner,name,desc))]
            a2=[(op,out) for _,op,out in instr(find(d,owner,name,desc))]
            require(a1==a2,"UPSTREAM_ORIGINAL_METHOD_CHANGED_"+name)
        w=load(a.derived,"classes3.dex")
        require(any(c.get_name()==WITNESS for c in w.get_classes()),
                "WITNESS_ONLY_IN_DISPOSABLE_CLASSES3")
        print("P208_ONLY_FIRST_COROUTINE_MARKER_PLUS_PC3912_P40_DENY=PASS")
        print("P208_ORIGINAL_START2_OTHER_OPCODES_OPERANDS=PARITY")
        print("P208_ORIGINAL_START_PARENT_BOOT_ONCREATE_PARITY=PASS")
        print("P208_JAVA_WITNESS_ONLY_DISPOSABLE_CLASSES3=PASS")
        print("P208_ORIGINAL_CHILD_PROCESS_OWNER=NOT_ATTESTED")
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P208_COROUTINE_DEX_PARITY_FAIL_CLOSED",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
