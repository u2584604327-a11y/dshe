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
        calls=[pos for pos,insn in rows if
            insn.get_name()=="invoke-virtual" and
            "Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;" in insn.get_output()]
        need(calls==[3912],"ORIGINAL_PC3912_UNIQUE")
        guards=[pos for pos,insn in rows
            if pos<3912 and insn.get_name().startswith("if-")]
        jumps=[pos for pos,insn in rows
            if pos<3912 and insn.get_name().startswith("goto")]
        need(len(guards)>0,"ORIGINAL_PREPC3912_GUARD_COUNT")
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
