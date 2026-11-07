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
FALL="Lcom/dsh/android/p209/P209PreCallWitness;->markFallthrough()V"
TARGET="Lcom/dsh/android/p209/P209PreCallWitness;->markTakenTarget()V"
POST="Lcom/dsh/android/p209/P209PreCallWitness;->markAfterThrowOnFailure()V"
P208="Lcom/dsh/android/p208/P208StartCoroutineWitness;->mark()V"
OLD="Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
NEW="Lcom/dsh/android/p40/P40ProcessBridge;->start(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;"
class Deny(Exception):pass
def require(v,label):
    if not v:raise Deny("P209_PRE_PC3912_DENY_"+label)
def ins(method):
    return [(pc,i.get_name(),i.get_output()) for pc,i in method.get_instructions_idx()]
def compare(original,derived):
    before=list(original.get_instructions_idx())
    after=list(derived.get_instructions_idx())
    def match(ins,sym):return ins.get_name()=="invoke-static" and sym in ins.get_output()
    markers=[[k for k,(_,ins) in enumerate(after) if match(ins,sym)]
             for sym in (P208,GUARD,FALL,TARGET,POST,PRE)]
    require(markers[0]==[0] and all(len(v)==1 for v in markers[1:]),
            "EXACT_SIX_DISPOSABLE_MARKERS")
    gi,fi,ti,xi,pi=(v[0] for v in markers[1:])
    require(0<gi<fi<ti<xi<pi and gi+2==fi and xi==ti+2 and
            after[gi+1][1].get_name()=="if-eqz" and
            after[fi+1][1].get_name()=="if-eq" and
            after[ti+1][1].get_name()=="invoke-static/range" and
            "Lkotlin/ResultKt;->throwOnFailure(" in after[xi-1][1].get_output() and
            after[xi+1][1].get_name()=="iget-object" and
            after[pi+1][1].get_name()=="invoke-static" and
            NEW in after[pi+1][1].get_output(),
            "ORIGINAL_PC26_PC30_PC176_PC182_PC3912_ORDER")
    original_first=[(pc,ins) for pc,ins in before if ins.get_name().startswith("if-")]
    require(original_first and original_first[0][0]==26 and
            original_first[0][1].get_name()=="if-eqz" and
            26+original_first[0][1].get_length()==30 and
            26+2*original_first[0][1].get_ref_off()==176,
            "ORIGINAL_SIGNED_PC26_TWO_SUCCESSORS_PINNED")
    omit={0,gi,fi,ti,xi,pi}
    aligned=[item for k,item in enumerate(after) if k not in omit]
    require(len(before)==len(aligned),"ORIGINAL_INSTRUCTION_COUNT_EXCEPT_SIX")
    mapping={opc:dpc for (opc,_),(dpc,_) in zip(before,aligned)}
    require(len(mapping)==len(before) and 176 in mapping and 182 in mapping and
            aligned[[pc for pc,_ in before].index(176)][1].get_name()=="invoke-static/range" and
            aligned[[pc for pc,_ in before].index(182)][1].get_name()=="iget-object" and
            after[xi-1][0]==mapping[176] and after[xi+1][0]==mapping[182],
            "ORIGINAL_PC176_PC182_EXACT_POSTCALL_PROOF")
    target_marker_pc=after[ti][0]
    require(after[ti+1][0]==mapping[176],"TAKEN_MARKER_PRECISELY_BEFORE_ORIGINAL_PC176")
    transformed=[]
    branch_count=0
    for k,((pc,orig),(dpc,der)) in enumerate(zip(before,aligned)):
        op,dop=orig.get_name(),der.get_name()
        out,dout=orig.get_output(),der.get_output()
        if op.startswith("if-") or op in ("goto","goto/16","goto/32"):
            require(op==dop and orig.get_length()==der.get_length(),
                    "BRANCH_OPCODE_OR_WIDTH_CHANGED_INDEX_"+str(k))
            original_dest=pc+2*orig.get_ref_off()
            derived_dest=dpc+2*der.get_ref_off()
            require(original_dest in mapping,"ORIGINAL_BRANCH_TARGET_NOT_MAPPED")
            expected=(target_marker_pc if original_dest==176 else mapping[original_dest])
            require(derived_dest==expected,
                    "ORIGINAL_BRANCH_RELOCATION_CHANGED_TARGET_INDEX_"+str(k))
            if op.startswith("if-"):
                require(out.rsplit(",",1)[0]==dout.rsplit(",",1)[0],
                        "IF_REGISTER_OPERAND_DRIFT_INDEX_"+str(k))
            branch_count+=1
            continue
        if op==dop and out==dout:continue
        valid=(pc==3912 and op=="invoke-virtual" and dop=="invoke-static"
               and out.endswith(OLD) and dout.endswith(NEW)
               and out[:-len(OLD)]==dout[:-len(NEW)])
        require(valid,"ORIGINAL_NONBRANCH_OPCODE_OPERAND_DRIFT_INDEX_"+str(k))
        transformed.append(pc)
    require(branch_count>=2 and transformed==[3912],
            "ORIGINAL_BRANCH_AND_ONLY_PC3912_REWRITE")
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
                    require(PRE not in out and P208 not in out and GUARD not in out and FALL not in out and TARGET not in out and POST not in out,
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
        print("P209_START2_ENTRY_PC26_PC30_PC176_PC182_PC3912_SIX_TEST_MARKERS=PASS")
        print("P209_START2_ORIGINAL_ALL_OTHER_OPCODES_OPERANDS=PARITY")
        print("P209_ORIGINAL_UPSTREAM_ENGINE_BOOT_ONCREATE=PARITY")
        print("P209_FIRST_GUARD_MATCHES_SIGNED_ORIGINAL=PASS")
        print("P209_ALL_ORIGINAL_BRANCH_TARGETS_RELOCATED_EXACTLY=PASS")
        print("P209_PC26_FALLTHROUGH_PC30_MARKER_ONLY_TEST_DEX=PASS")
        print("P209_PC26_TAKEN_PC176_BRANCH_TARGET_MARKER_ONLY_TEST_DEX=PASS")
        print("P209_PC176_NORMAL_RETURN_MARKER_AFTER_EXACT_THROWONFAILURE=PASS")
        print("P209_FIRST_GUARD_SIGNED_PC="+str([(pc,op) for pc,op,out in ins(prev.find(o,prev.START2,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")) if op.startswith("if-")][0][0]))
        print("P209_PRE_PC3912_MARKER_ONLY_IN_DISPOSABLE_CLASSES3=PASS")
        print("P209_REAL_PC3912_RUNTIME_EXECUTION=NOT_ATTESTED")
    except (Deny,prev.Denied,p208.Refused) as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P209_EXACT_ORIGINAL_PRE_PC3912_DEX_FAIL_CLOSED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
