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
    def is_marker(instr,sym):
        return instr.get_name()=="invoke-static" and sym in instr.get_output()
    first=[k for k,(_,inst) in enumerate(after) if is_marker(inst,P208)]
    guard=[k for k,(_,inst) in enumerate(after) if is_marker(inst,GUARD)]
    fall=[k for k,(_,inst) in enumerate(after) if is_marker(inst,FALL)]
    precall=[k for k,(_,inst) in enumerate(after) if is_marker(inst,PRE)]
    original_conds=[(pc,inst) for pc,inst in before if inst.get_name().startswith("if-")]
    require(original_conds and original_conds[0][0]==26 and
            original_conds[0][1].get_name()=="if-eqz" and
            original_conds[0][0]+original_conds[0][1].get_length()==30 and
            original_conds[0][0]+2*original_conds[0][1].get_ref_off()==176,
            "ORIGINAL_SIGNED_PC26_IF_EQZ_BOTH_SUCCESSORS_PINNED")
    require(first==[0] and len(guard)==len(fall)==len(precall)==1 and
            0<guard[0]<fall[0]<precall[0],
            "EXACT_FOUR_DISPOSABLE_MARKER_POSITIONS")
    gi,fi,pi=guard[0],fall[0],precall[0]
    require(gi+2==fi and after[gi+1][1].get_name()=="if-eqz" and
            after[fi+1][1].get_name()=="if-eq" and
            not any(ins.get_name().startswith("if-") for _,ins in after[:gi]),
            "FALLTHROUGH_MARKER_ONLY_AFTER_FIRST_ORIGINAL_IF")
    require(pi+1<len(after) and after[pi+1][1].get_name()=="invoke-static" and
            NEW in after[pi+1][1].get_output(),
            "PRE_MARKER_IMMEDIATELY_BEFORE_TYPED_P40_DENY")
    aligned=[item for k,item in enumerate(after) if k not in (0,gi,fi,pi)]
    require(len(before)==len(aligned),"ORIGINAL_INSTRUCTION_COUNT_EXCEPT_FOUR")
    orig_to_derived={oldpc:newpc for (oldpc,_),(newpc,_) in zip(before,aligned)}
    require(len(orig_to_derived)==len(before),"UNIQUE_ORIGINAL_ALIGNMENT")
    spawn_changes=[]
    branch_checks=0
    for pos,((pc,oi),(dpc,di)) in enumerate(zip(before,aligned)):
        op,dop=oi.get_name(),di.get_name()
        out,dout=oi.get_output(),di.get_output()
        if (op.startswith("if-") or op in ("goto","goto/16","goto/32")):
            require(op==dop and oi.get_length()==di.get_length(),
                    "BRANCH_OPCODE_OR_WIDTH_DRIFT_INDEX_"+str(pos))
            otarget=pc+2*oi.get_ref_off()
            dtarget=dpc+2*di.get_ref_off()
            require(otarget in orig_to_derived and
                    orig_to_derived[otarget]==dtarget,
                    "ORIGINAL_BRANCH_TARGET_CHANGED_INDEX_"+str(pos))
            if op.startswith("if-"):
                require(out.rsplit(",",1)[0]==dout.rsplit(",",1)[0],
                        "ORIGINAL_IF_REGISTER_OPERANDS_CHANGED_INDEX_"+str(pos))
            branch_checks+=1
            continue
        if op==dop and out==dout:continue
        allow=(pc==3912 and op=="invoke-virtual" and dop=="invoke-static" and
               out.endswith(OLD) and dout.endswith(NEW) and
               out[:-len(OLD)]==dout[:-len(NEW)])
        require(allow,"ORIGINAL_NONBRANCH_OPCODE_OR_OPERAND_CHANGED_INDEX_"+str(pos))
        spawn_changes.append(pc)
    require(spawn_changes==[3912],"ONLY_ORIGINAL_PC3912_P40_DENY_REWRITE")
    require(branch_checks>=1,"NO_ORIGINAL_BRANCH_EDGE_VERIFIED")
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
                    require(PRE not in out and P208 not in out and GUARD not in out and FALL not in out,
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
        print("P209_START2_ENTRY_PC26_PC30_AND_PC3912_FOUR_TEST_MARKERS=PASS")
        print("P209_START2_ORIGINAL_ALL_OTHER_OPCODES_OPERANDS=PARITY")
        print("P209_ORIGINAL_UPSTREAM_ENGINE_BOOT_ONCREATE=PARITY")
        print("P209_FIRST_GUARD_MATCHES_SIGNED_ORIGINAL=PASS")
        print("P209_ALL_ORIGINAL_BRANCH_TARGETS_RELOCATED_EXACTLY=PASS")
        print("P209_PC26_FALLTHROUGH_PC30_MARKER_ONLY_TEST_DEX=PASS")
        print("P209_FIRST_GUARD_SIGNED_PC="+str([(pc,op) for pc,op,out in ins(prev.find(o,prev.START2,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")) if op.startswith("if-")][0][0]))
        print("P209_PRE_PC3912_MARKER_ONLY_IN_DISPOSABLE_CLASSES3=PASS")
        print("P209_REAL_PC3912_RUNTIME_EXECUTION=NOT_ATTESTED")
    except (Deny,prev.Denied,p208.Refused) as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P209_EXACT_ORIGINAL_PRE_PC3912_DEX_FAIL_CLOSED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
