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
        cls=[c for c in dex.get_classes() if c.get_name()==OWNER]
        need(len(cls)==1,"P47_CLASS")
        methods=[m for m in cls[0].get_methods() if m.get_name()=="startOrDeny"]
        need(len(methods)==1,"EXACT_STARTORDENY")
        ins=[(i.get_name(),i.get_output()) for _,i in methods[0].get_instructions_idx()]
        log=[i for i,(op,out) in enumerate(ins) if
             "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I" in out]
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
        print("P209_DISPOSABLE_P47_MAIN_GATE_BINARY_LOGS=PASS")
        print("P209_ORIGINAL_P47_MAIN_THROWS_AFTER_FINAL_MARKER=PASS")
        print("P209_P47_PRIMARY_NO_HOST_PROCESSBUILDER_START=PASS")
        print("P209_P47_SECONDARY_MODES_NOT_INSTRUMENTED=PASS")
    except Exception:
        print("P209_DISPOSABLE_GATE_BINARY_FAIL_CLOSED",file=sys.stderr);sys.exit(2)
if __name__=="__main__":main()
