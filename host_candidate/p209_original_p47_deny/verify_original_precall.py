#!/usr/bin/env python3
"""P209 exact signed original start$2 semantic parity with two test-only witnesses.
Never claims original PC3912 executed without same-run Android35 Logcat proof.
"""
import sys
from pathlib import Path
sys.path.insert(0,"host_candidate/p208_original_start_coroutine")
import verify_derived as prev
import patch_ci_only as p208
from androguard.core.dex import DEX
import zipfile
PRE="Lcom/dsh/android/p209/P209PreCallWitness;->mark()V"
GUARD="Lcom/dsh/android/p209/P209PreCallWitness;->markFirstGuard()V"
P208="Lcom/dsh/android/p208/P208StartCoroutineWitness;->mark()V"
OLD="Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
NEW="Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
class Deny(Exception):pass
def require(v,label):
    if not v:raise Deny("P209_PRE_PC3912_DENY_"+label)
def ins(method):
    return [(pc,i.get_name(),i.get_output()) for pc,i in method.get_instructions_idx()]
def compare(original,derived):
    a=ins(original);b=ins(derived)
    first=[i for i,(_,op,out) in enumerate(b) if op=="invoke-static" and P208 in out]
    approach=[i for i,(_,op,out) in enumerate(b) if op=="invoke-static" and GUARD in out]
    precall=[i for i,(_,op,out) in enumerate(b) if op=="invoke-static" and PRE in out]
    cond=[(pc,op) for pc,op,out in a if op.startswith("if-")]
    require(cond and 0<cond[0][0]<3912 and cond[0][1].startswith("if-"),
            "SIGNED_FIRST_ORIGINAL_GUARD_BEFORE_PC3912")
    expected_original_cond_op=cond[0][1]
    require(first==[0] and len(approach)==1 and len(precall)==1 and
            0<approach[0]<precall[0],"EXACT_THREE_TEST_MARKER_POSITIONS")
    guard_idx=approach[0];pre_idx=precall[0]
    require(guard_idx+1<len(b) and b[guard_idx+1][1]==expected_original_cond_op and
            sum(op.startswith("if-") for _,op,out in b[:guard_idx])==0,
            "GUARD_MARKER_IMMEDIATELY_BEFORE_FIRST_IF_NE")
    require(pre_idx+1<len(b) and b[pre_idx+1][1]=="invoke-static" and
            NEW in b[pre_idx+1][2],"PRE_MARKER_IMMEDIATELY_BEFORE_P40")
    remaining=[row for i,row in enumerate(b) if i not in (0,guard_idx,pre_idx)]
    require(len(a)==len(remaining),"ORIGINAL_INSTRUCTION_COUNT_EXCEPT_THREE")
    replaced=[]
    for pos,(o,d) in enumerate(zip(a,remaining)):
        pc,op,out=o;_,dop,dout=d
        if op==dop and out==dout:continue
        valid=(pc==3912 and op=="invoke-virtual" and dop=="invoke-static"
            and out.endswith(OLD) and dout.endswith(NEW)
            and out[:-len(OLD)]==dout[:-len(NEW)])
        require(valid,"UNAUTHORIZED_ORIGINAL_OP_OR_OPERAND_INDEX_"+str(pos))
        replaced.append(pc)
    require(replaced==[3912],"ONLY_ORIGINAL_PC3912_P40_REDIRECT")
def main():
    if len(sys.argv)!=3:sys.exit(2)
    try:
        original,derived=map(Path,sys.argv[1:])
        p208.verify_signed_original_coroutine(original)
        o=prev.load(original);d=prev.load(derived)
        compare(prev.find(o,prev.START2,"invokeSuspend",
                "(Ljava/lang/Object;)Ljava/lang/Object;"),
                prev.find(d,prev.START2,"invokeSuspend",
                "(Ljava/lang/Object;)Ljava/lang/Object;"))
        for c in d.get_classes():
            for method in c.get_methods():
                if method.get_code() is None:continue
                if c.get_name()==prev.START2 and method.get_name()=="invokeSuspend":continue
                for _,instr in method.get_instructions_idx():
                    out=instr.get_output()
                    require(PRE not in out and P208 not in out and GUARD not in out,
                            "EXTRA_MARKER_OUTSIDE_ORIGINAL_COROUTINE")
        for owner,name,desc in [
             (prev.ENGINE,"start","(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"),
             (prev.ACTIVITY,"onCreate","(Landroid/os/Bundle;)V"),
             (prev.ACTIVITY,"bootEngine","()V"),
             (prev.BOOT,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")]:
            before=prev.find(o,owner,name,desc)
            after=prev.find(d,owner,name,desc)
            require([(op,out) for _,op,out in ins(before)]==
                    [(op,out) for _,op,out in ins(after)],
                    "ORIGINAL_UPSTREAM_METHOD_DRIFT_"+name)
        with zipfile.ZipFile(derived) as z:dex=DEX(z.read("classes3.dex"))
        owners={c.get_name() for c in dex.get_classes()}
        require("Lcom/dsh/android/p208/P208StartCoroutineWitness;" in owners and
                "Lcom/dsh/android/p209/P209PreCallWitness;" in owners,
                "BOTH_TEST_ONLY_CLASSES3_WITNESSES")
        print("P209_START2_ENTRY_FIRST_GUARD_AND_PC3912_THREE_TEST_MARKERS=PASS")
        print("P209_START2_ORIGINAL_ALL_OTHER_OPCODES_OPERANDS=PARITY")
        print("P209_ORIGINAL_UPSTREAM_ENGINE_BOOT_ONCREATE=PARITY")
        print("P209_FIRST_GUARD_MATCHES_SIGNED_ORIGINAL=PASS")
        print("P209_FIRST_GUARD_SIGNED_PC="+str([(pc,op) for pc,op,out in ins(prev.find(o,prev.START2,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")) if op.startswith("if-")][0][0]))
        print("P209_PRE_PC3912_MARKER_ONLY_IN_DISPOSABLE_CLASSES3=PASS")
        print("P209_REAL_PC3912_RUNTIME_EXECUTION=NOT_ATTESTED")
    except (Deny,prev.Denied,p208.Refused) as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P209_EXACT_ORIGINAL_PRE_PC3912_DEX_FAIL_CLOSED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
