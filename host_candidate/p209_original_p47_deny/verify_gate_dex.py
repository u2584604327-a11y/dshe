#!/usr/bin/env python3
"""P209 assert disposable compiled P47 primary exact gate and no host starts."""
import argparse,sys,zipfile
from androguard.core.dex import DEX
OWNER="Lcom/dsh/android/p47/P47LaunchGate;"
HOST="Ljava/lang/ProcessBuilder;->start("
def need(v,code):
    if not v:raise ValueError("P209_DENY_"+code)
def main():
    x=argparse.ArgumentParser();x.add_argument("derived");a=x.parse_args()
    try:
        with zipfile.ZipFile(a.derived) as f:
            dex=DEX(f.read("classes3.dex"))
            dex1=DEX(f.read("classes.dex"))
        cls=[c for c in dex.get_classes() if c.get_name()==OWNER]
        need(len(cls)==1,"P47_CLASS")
        methods=[m for m in cls[0].get_methods() if m.get_name()=="startOrDeny"]
        need(len(methods)==1,"EXACT_STARTORDENY")
        ins=[(i.get_name(),i.get_output()) for _,i in methods[0].get_instructions_idx()]
        log=[i for i,(op,out) in enumerate(ins) if
             "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I" in "".join(out.split())]
        need(len(log)==3 and log==sorted(log),"EXACT_THREE_GATE_LOGS")
        need(any(op=="throw" for op,out in ins) and
             log[-1]<max(i for i,(op,out) in enumerate(ins) if op=="throw"),
             "FINAL_MARKER_BEFORE_THROW")
        need(not any(HOST in out for op,out in ins if op.startswith("invoke-")),
             "HOST_PROCESSBUILDER_NOT_ALLOWED")
        for method in cls[0].get_methods():
            if method.get_name() in ("probeOrDeny","configOrDeny"):
                need(not any("Landroid/util/Log;->i(" in i.get_output()
                    for _,i in method.get_instructions_idx()),"SECONDARY_GATE_DRIFT")
        p40=[c for c in dex1.get_classes() if
              c.get_name()=="Lcom/dsh/android/p40/P40ProcessBridge;"]
        need(len(p40)==1,"EXACT_P40_CLASS")
        start=[m for m in p40[0].get_methods() if m.get_name()=="start"]
        need(len(start)==1 and start[0].get_code() is not None,
             "EXACT_P40_START_METHOD")
        instructions=[(i.get_name(),i.get_output()) for _,i in start[0].get_instructions_idx()]
        logger=[idx for idx,(op,out) in enumerate(instructions)
           if op.startswith("invoke-") and
           "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I" in "".join(out.split())]
        to_gate=[idx for idx,(op,out) in enumerate(instructions)
           if op=="invoke-static" and
           "Lcom/dsh/android/p47/P47LaunchGate;->startOrDeny(" in out]
        categories=[idx for idx,(op,out) in enumerate(instructions)
           if op=="const-string" and "P209_P40_BRIDGE_ENTRY=OBSERVED" in out]
        need(len(logger)==1 and len(to_gate)==1 and len(categories)==1 and
             categories[0]<logger[0]<to_gate[0],"EXACT_P40_LOG_BEFORE_TYPED_DENY")
        need(start[0].get_code().get_registers_size()==3,"EXACT_P40_TEST_REGISTERS")
        need(not any(HOST in out for op,out in instructions if op.startswith("invoke-")),
             "P40_HOST_PROCESS_NOT_PERMITTED")
        print("P209_DISPOSABLE_P40_ONE_LOG_BEFORE_P47_DENY=PASS")
        # P209 read-only original v138 path audit: static CFG is not runtime proof.
        import pathlib
        import hashlib
        import importlib.util
        source=pathlib.Path(".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
        need(source.is_file(),"SIGNED_SOURCE_REQUIRED")
        need(hashlib.sha256(source.read_bytes()).hexdigest()==
             "3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5",
             "SIGNED_SOURCE_SHA")
        with zipfile.ZipFile(source) as signed:
            original=DEX(signed.read("classes.dex"))
        start=[m for c in original.get_classes()
            if c.get_name()=="Lcom/dsh/android/EngineManager$start$2;"
            for m in c.get_methods() if m.get_name()=="invokeSuspend"]
        need(len(start)==1,"ORIGINAL_START2_SIGNATURE")
        rows=list(start[0].get_instructions_idx())
        # P209 purely read-only bounded original v138 opcode boundary after
        # PC176. Never treat a static opcode sequence as Android execution.
        pc176=[i for i,(pc,ins) in enumerate(rows) if pc==176]
        need(len(pc176)==1 and rows[pc176[0]][1].get_name()=="invoke-static/range",
             "SIGNED_ORIGINAL_PC176_STATIC_INVOKE")
        follow=pc176[0]+1
        need(follow<len(rows),"SIGNED_PC176_NEXT_OPCODE")
        pair=rows[follow][1].get_name().startswith("move-result")
        if pair:follow+=1
        need(follow<len(rows) and rows[follow][0]<3912 and
             not rows[follow][1].get_name().startswith("move-result"),
             "PC176_POST_INVOKE_SAFE_OPCODE_BOUND")
        print("P209_SIGNED_PC176_ORIGINAL_OPCODE=invoke-static/range")
        print("P209_SIGNED_PC176_HAS_MOVE_RESULT="+("YES" if pair else "NO"))
        print("P209_SIGNED_PC176_NEXT_SAFE_PC="+str(rows[follow][0]))
        print("P209_SIGNED_PC176_NEXT_SAFE_OPCODE="+rows[follow][1].get_name())
        for pc,ins in rows[pc176[0]:min(follow+9,len(rows))]:
            if pc>=3912:break
            print("P209_PC176_STATIC_WINDOW_PC="+str(pc)+",OP="+ins.get_name())
        # Signed-public-DEX metadata only; not a runtime execution witness.
        import re
        output=rows[pc176[0]][1].get_output()
        call=re.search(r"L[^;,\s]+;->[A-Za-z0-9_$<>]+\(",output)
        need(call is not None,"PC176_ORIGINAL_CALLEE_DESCRIPTOR")
        callee=call.group(0).removesuffix("(")
        need(len(callee)<=220 and "\n" not in callee,
             "PC176_CALLEE_OUTPUT_BOUND")
        print("P209_SIGNED_PC176_STATIC_CALLEE="+callee)
        code=start[0].get_code()
        need(code is not None,"PC176_SIGNED_METHOD_CODE_REQUIRED")
        items=code.get_tries() or []
        need(len(items)<=128,"PC176_TRY_RANGE_COUNT_BOUND")
        bounds=[(2*t.get_start_addr(),
                 2*(t.get_start_addr()+t.get_insn_count())) for t in items]
        need(all(0<=begin<end<=code.get_insns_size()*2
                 for begin,end in bounds),"PC176_TRY_BOUNDS_INVALID")
        for pc,label in ((176,"PC176"),(rows[follow][0],"POST176")):
            covers=[(a,b) for a,b in bounds if a<=pc<b]
            print("P209_SIGNED_"+label+"_TRY_RANGE_COUNT="+str(len(covers)))
            for begin,end in covers[:3]:
                print("P209_SIGNED_"+label+"_TRY_START_PC="+str(begin))
                print("P209_SIGNED_"+label+"_TRY_END_EXCLUSIVE_PC="+str(end))
        print("P209_SIGNED_PC176_CATCH_HANDLER_DISPATCH=NOT_TRACED")
        print("P209_SIGNED_PC176_RUNTIME_EXCEPTION=NOT_ATTESTED")
        print("P209_PC176_CALLEE_AND_TRY_BOUNDS_STATIC_AUDIT=PASS")
        # Read-only Kotlin Result parameter provenance, never a success claim.
        # invokeSuspend(Object) is an instance method: p1 is the final input
        # register in the original signed DEX register window.
        ins_size=code.get_ins_size()
        reg_size=code.get_registers_size()
        need(ins_size==2 and reg_size>=2,
             "PC176_INVOKESUSPEND_PARAM_LAYOUT")
        call_prefix=output.split("Lkotlin/ResultKt;->throwOnFailure",1)[0]
        raw_args=[int(x) for x in re.findall(r"\\bv(\\d+)\\b",call_prefix)]
        if raw_args and len(raw_args)<=2 and len(set(raw_args))==1:
            relation=("INVOKESUSPEND_RESULT_P1" if raw_args[0]==reg_size-1
                      else "OTHER_LOCAL_OR_COPIED_REGISTER")
        else:
            relation="UNDETERMINED"
        print("P209_SIGNED_PC176_THROW_ARG_RELATION="+relation)
        print("P209_SIGNED_PC176_THROW_ARG_RUNTIME_VALUE=NOT_ATTESTED")
        # The next state guards are structural, not taken-edge witnesses.
        by_original_pc={pc:ins for pc,ins in rows}
        for guard,expected in ((202,"if-eqz"),(214,"if-ne")):
            item=by_original_pc.get(guard)
            need(item is not None and item.get_name()==expected,
                 "PC176_POSTCALL_STATE_GUARD_DRIFT")
            sequential=guard+item.get_length()
            destination=guard+2*item.get_ref_off()
            need(sequential in by_original_pc and destination in by_original_pc
                 and sequential!=destination,
                 "PC176_POSTCALL_STATE_GUARD_TARGET_DRIFT")
            print("P209_SIGNED_STATE_GUARD_PC="+str(guard)+
                  ",OP="+expected+",FALL="+str(sequential)+
                  ",TAKEN="+str(destination))
        print("P209_SIGNED_STATE_GUARDS_RUNTIME_PATH=NOT_ATTESTED")
        print("P209_ORIGINAL_PC176_POST_CALL_STATIC_AUDIT=PASS")
        print("P209_ORIGINAL_PC176_CALL_NORMAL_RETURN=NOT_ATTESTED")
        calls=[pos for pos,insn in rows if
            insn.get_name()=="invoke-virtual" and
            "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;" in insn.get_output()]
        need(calls==[3912],"ORIGINAL_PC3912_UNIQUE")
        guards=[pos for pos,insn in rows
            if pos<3912 and insn.get_name().startswith("if-")]
        jumps=[pos for pos,insn in rows
            if pos<3912 and insn.get_name().startswith("goto")]
        need(len(guards)>0,"ORIGINAL_PREPC3912_GUARD_COUNT")
        # Conservative normal-edge CFG. Switch/payload and exception edges
        # are deliberately NOT expanded; never claim this proves Android reach.
        import importlib
        helper=pathlib.Path(__file__).resolve().parents[1]/"p204_oncreate_pc430"
        sys.path.insert(0,str(helper))
        cfg=importlib.import_module("audit_original_oncreate_pc430")
        nodes=[cfg.instruction(pc,inst.get_name(),inst.get_length(),
            inst.get_ref_off() if cfg.is_cond(inst.get_name()) or
              cfg.is_jump(inst.get_name()) else None)
            for pc,inst in rows]
        try:
            edges,unknown,by_pc=cfg.graph(nodes)
            need(3912 in by_pc,"PC3912_CFG_INSTRUCTION_BOUNDARY")
            # P209 read-only signed-original first real branch successors.
            # Static graph edges do not attest which Android runtime arm executed.
            earliest=[(pc,ins) for pc,ins in rows
                      if ins.get_name().startswith("if-")]
            need(len(earliest)>0 and earliest[0][0]==26,
                 "FIRST_SIGNED_GUARD_EXACT_PC26")
            guard_pc,guard_ins=earliest[0]
            fall=guard_pc+guard_ins.get_length()
            taken=guard_pc+2*guard_ins.get_ref_off()
            need(fall in by_pc and taken in by_pc and fall!=taken and
                 set(edges[guard_pc])=={fall,taken},
                 "FIRST_SIGNED_GUARD_EXACT_NORMAL_TWO_EDGES")
            fall_reaches=cfg.reachable(edges,fall,3912)
            taken_reaches=cfg.reachable(edges,taken,3912)
            print("P209_FIRST_SIGNED_CONDITION_PC="+str(guard_pc))
            print("P209_FIRST_SIGNED_CONDITION_OP="+guard_ins.get_name())
            print("P209_FIRST_GUARD_FALLTHROUGH_PC="+str(fall))
            print("P209_FIRST_GUARD_TAKEN_TARGET_PC="+str(taken))
            print("P209_FIRST_GUARD_FALLTHROUGH_OPCODE="+by_pc[fall]["op"])
            print("P209_FIRST_GUARD_TAKEN_TARGET_OPCODE="+by_pc[taken]["op"])
            print("P209_FIRST_GUARD_FALLTHROUGH_STATIC_PC3912="+
                  ("REACHABLE" if fall_reaches else "NOT_PROVEN_REACHABLE"))
            print("P209_FIRST_GUARD_TAKEN_STATIC_PC3912="+
                  ("REACHABLE" if taken_reaches else "NOT_PROVEN_REACHABLE"))
            print("P209_FIRST_GUARD_RUNTIME_SELECTED_ARM=NOT_ATTESTED")
            print("P209_SIGNED_FIRST_GUARD_TWO_NORMAL_EDGES=PASS")
            reachable=cfg.reachable(edges,0,3912)
            candidates=[]
            for node in nodes:
                at=node["pc"]
                if (at>=3912 or not cfg.is_cond(node["op"]) or
                    not cfg.reachable(edges,0,at)):
                    continue
                arms=[cfg.reachable(edges,d,3912) for d in edges[at]]
                if len(set(arms))>1:
                    candidates.append((at,node["op"]))
            print("P209_PC3912_CONSERVATIVE_NORMAL_CFG="+
                  ("REACHABLE" if reachable else "NOT_PROVEN_REACHABLE"))
            print("P209_PC3912_PRECALL_SPLIT_GUARD_COUNT="+str(len(candidates)))
            for at,op in candidates[:8]:
                print("P209_PC3912_PRECALL_GUARD_PC="+str(at)+",OP="+op)
            # Both branches' conservative reachability: never infer which
            # side the actual Android coroutine selected.
            for guard in (202,214):
                item=by_original_pc[guard]
                succ=(guard+item.get_length(),
                      guard+2*item.get_ref_off())
                if set(edges.get(guard,[]))==set(succ):
                    for label,target in zip(("FALL","TAKEN"),succ):
                        reach=cfg.reachable(edges,target,3912)
                        print("P209_SIGNED_STATE_GUARD_"+str(guard)+"_"+label+
                              "_PC3912="+("REACHABLE" if reach else
                              "NOT_PROVEN_REACHABLE"))
                else:
                    print("P209_SIGNED_STATE_GUARD_"+str(guard)+
                          "_PC3912=UNDETERMINED")
            print("P209_CFG_SWITCH_OR_PAYLOAD_UNEXPANDED="+str(len(unknown)))
        except cfg.Blocked:
            print("P209_PC3912_CONSERVATIVE_NORMAL_CFG=UNDETERMINED")
        print("P209_PC3912_EXCEPTION_HANDLER_EDGES=NOT_MODELED")
        print("P209_PC3912_RUNTIME_BRANCH_TAKEN=NOT_ATTESTED")
        print("P209_SIGNED_ORIGINAL_START2_PC3912_STATIC_AUDIT=PASS")
        print("P209_PRE_PC3912_CONDITIONAL_COUNT="+str(len(guards)))
        print("P209_PRE_PC3912_GOTO_COUNT="+str(len(jumps)))
        print("P209_REAL_ANDROID_PC3912_REACHED=NOT_ATTESTED")
        print("P209_DISPOSABLE_P47_MAIN_GATE_BINARY_LOGS=PASS")
        print("P209_ORIGINAL_P47_MAIN_THROWS_AFTER_FINAL_MARKER=PASS")
        print("P209_P47_PRIMARY_NO_HOST_PROCESSBUILDER_START=PASS")
        print("P209_P47_SECONDARY_MODES_NOT_INSTRUMENTED=PASS")
    except ValueError as denied:
        print(str(denied),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P209_DISPOSABLE_GATE_BINARY_FAIL_CLOSED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
