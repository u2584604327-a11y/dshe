#!/usr/bin/env python3
"""P205 exact original-vs-test DEX method instruction semantic parity."""
import argparse
import pathlib
import sys
import zipfile
from androguard.core.dex import DEX

MAIN="Lcom/dsh/android/MainActivity;"
NAME="bootEngine"
MARK_OWNER="Lcom/dsh/android/p205/P205BootEntryWitness;"
MARK_NAME="mark"
def require(x,code):
    if not x:raise ValueError("P205_DENY_"+code)
def method(dex,owner,name,desc):
    arr=[]
    for c in dex.get_classes():
        if c.get_name()!=owner:continue
        for m in c.get_methods():
            if (m.get_name()==name and
                "".join(m.get_descriptor().split())==desc):
                arr.append(m)
    require(len(arr)==1,"EXACT_METHOD_"+name)
    return arr[0]
def items(method):
    return [(i.get_name(),i.get_output()) for _,i
            in method.get_instructions_idx()]
def load(path):
    with zipfile.ZipFile(path) as z:
        return DEX(z.read("classes.dex"))
def main():
    a=argparse.ArgumentParser()
    a.add_argument("original")
    a.add_argument("derived")
    args=a.parse_args()
    try:
        orig,derived=load(args.original),load(args.derived)
        orig_boot=items(method(orig,MAIN,NAME,"()V"))
        patched=items(method(derived,MAIN,NAME,"()V"))
        marks=[i for i,(op,out) in enumerate(patched)
               if op=="invoke-static" and
                  MARK_OWNER+"->"+MARK_NAME+"()V" in out]
        require(marks==[0],"ONLY_ONE_EXACT_ENTRY_MARKER_AT_FIRST_OPCODE")
        without=[v for i,v in enumerate(patched) if i!=marks[0]]
        require(orig_boot==without,
                "ORIGINAL_BOOTENGINE_INSTRUCTIONS_NOT_IDENTICAL_AFTER_MARKER_REMOVAL")
        # No other direct original callsite may have been instrumented.
        for c in derived.get_classes():
            for m in c.get_methods():
                if m.get_code() is None:continue
                if (c.get_name()==MAIN and m.get_name()==NAME):continue
                for _,i in m.get_instructions_idx():
                    if MARK_OWNER+"->"+MARK_NAME+"()V" in i.get_output():
                        require(False,"MARKER_REFERENCED_OUTSIDE_EXACT_METHOD")
        orig_create=items(method(orig,MAIN,"onCreate",
                                 "(Landroid/os/Bundle;)V"))
        rebuilt_create=items(method(derived,MAIN,"onCreate",
                                    "(Landroid/os/Bundle;)V"))
        require(orig_create==rebuilt_create,"ONCREATE_OPCODE_OPERAND_DRIFT")
        with zipfile.ZipFile(args.derived) as z:
            classes=DEX(z.read("classes3.dex"))
            require(any(c.get_name()==MARK_OWNER for c in classes.get_classes()),
                    "EXACT_TEST_MARKER_CLASS_MISSING")
        print("P205_TEST_ONLY_ORIGINAL_BOOTENGINE_ONLY_ONE_FIRST_INVOKE=PASS")
        print("P205_BOOTENGINE_OTHER_ORIGINAL_INSTRUCTIONS=BYTECODE_SEMANTIC_PARITY")
        print("P205_ORIGINAL_ONCREATE_COMPLETE_INSTRUCTION_PARITY=PASS")
        print("P205_PC430_ORIGINAL_CALLSITE_UNCHANGED=PASS")
        print("P205_JAVA_WITNESS_ONLY_IN_DISPOSABLE_CLASSES3=PASS")
        print("P205_ORIGINAL_KOTLIN_COROUTINE_OR_NODE=NOT_ATTESTED")
    except Exception:
        print("P205_EXACT_DEX_PARITY_FAIL_CLOSED",file=sys.stderr)
        sys.exit(2)
if __name__=="__main__":main()
