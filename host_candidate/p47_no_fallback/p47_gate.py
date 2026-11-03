#!/usr/bin/env python3
"""P47: only change the exact P40 generated *main* DEX trampoline.
Original unmodified EngineManager probeBoot and runDumpConfig are untouched.
Never produces a release or modifies the signed owner APK.
"""
import argparse
import os
import pathlib
import re
import zipfile
from androguard.core.dex import DEX
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from p40_exact_trampoline import find_methods, TARGET, CLASS, ORIGINAL, TRAMPOLINE

BRIDGE_SOURCE = "invoke-virtual {p0}, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
DENY = "Lcom/dsh/android/p47/P47LaunchGate;->startOrDeny(Ljava/lang/ProcessBuilder;)"
BRIDGE_REPLACEMENT = "invoke-static {p0}, " + DENY + "Ljava/lang/Process;"

def need(ok,label):
    if not ok:
        raise RuntimeError("P47_BLOCKED_" + label)


# P181: this is a binary-level DENY-only convergence for the exact v138 DEX.
# It does not start Node, inject a real Broker, or authorize original services.
# The pinned v138 EngineManager.smali contains exactly one probeBoot and
# runDumpConfig ProcessBuilder.start; main was already redirected by P40.
P181_CALL=re.compile(
    r"(?m)^([ \t]*)invoke-virtual[ \t]+\{([vp][0-9]+)\},[ \t]+"
    r"Ljava/lang/ProcessBuilder;->start\(\)Ljava/lang/Process;[ \t]*$")
def p181_secondary_denial(root):
    require=os.environ.get("P181_THREE_ORIGINAL_START_DENY")=="1"
    if not require:return
    need(os.environ.get("P47_NO_HOST_FALLBACK")=="1" and
         os.environ.get("P51_SIDE_BY_SIDE","0")=="0",
         "P181_REQUIRES_EXACT_ORIGINAL_WITH_P47")
    path=root / "smali/com/dsh/android/EngineManager.smali"
    need(path.is_file() and not path.is_symlink(),"P181_REAL_MAIN_DEX_ENGINE_REQUIRED")
    text=path.read_text(encoding="utf8")
    need(len(P181_CALL.findall(text))==2,"P181_EXACT_TWO_UNPROTECTED_SITES")
    for name in ("probeBoot","runDumpConfig"):
        starts=list(re.finditer(r"(?m)^\.method[^\n]*\b"+name+r"\([^\n]*$",text))
        need(len(starts)==1,"P181_ONE_METHOD_"+name)
        begin=starts[0].start()
        ending=text.find(".end method",starts[0].end())
        need(ending>=0,"P181_METHOD_END_"+name)
        ending+=len(".end method")
        section=text[begin:ending]
        need(len(P181_CALL.findall(section))==1,"P181_EXACT_ONE_START_"+name)
        changed=P181_CALL.sub(
            lambda m:m.group(1)+"invoke-static {"+m.group(2)+"}, "+
            TRAMPOLINE+"Ljava/lang/Process;",section,count=1)
        need(changed!=section and not P181_CALL.search(changed),
             "P181_SITE_NOT_REWRITTEN_"+name)
        text=text[:begin]+changed+text[ending:]
    need(not P181_CALL.search(text) and text.count(TRAMPOLINE)==2,
         "P181_SECONDARY_HOST_LAUNCH_REMAINS")
    path.write_text(text,encoding="utf8")
    print("P181_ORIGINAL_V138_PROBE_CONFIG_REDIRECTED_TO_P47_DENY=PASS")
    print("P181_ORIGINAL_NODE_READY_AND_THREE_TYPED_BROKER=NOT_WIRED")

def patch(decoded):
    root=pathlib.Path(decoded)
    file=root / "smali/com/dsh/android/p40/P40ProcessBridge.smali"
    need(file.is_file() and not file.is_symlink(),"BRIDGE_MISSING")
    data=file.read_text(encoding="utf-8")
    need(data.count(BRIDGE_SOURCE)==1,"ORIGINAL_BRIDGE_START_DRIFT")
    need("P47LaunchGate" not in data,"BRIDGE_ALREADY_MODIFIED")
    modified=data.replace(BRIDGE_SOURCE,BRIDGE_REPLACEMENT)
    need(modified.count(BRIDGE_REPLACEMENT)==1,"DENY_NOT_UNIQUE")
    file.write_text(modified,encoding="utf-8")
    p181_secondary_denial(root)
    print("P47_EXACT_ORIGINAL_BRIDGE_INTERPOSED=PASS_STATIC")
    print("P47_DIRECT_HOST_PROCESSBUILDER_START=REMOVED_FROM_MAIN_ENGINE_BRIDGE")
    print("P47_OTHER_ORIGINAL_ENGINE_START_SITES=UNCHANGED")
    print("P47_REAL_PRODUCTION_NODE_ENGINE_ISOLATED=NO")

def verify(apk):
    m=find_methods(apk)
    target="Lcom/dsh/android/EngineManager$start$2;->invokeSuspend"
    bridge=CLASS+"->start"
    probe="Lcom/dsh/android/EngineManager;->probeBoot"
    dump="Lcom/dsh/android/EngineManager;->runDumpConfig"
    need(all(x in m for x in (target,bridge,probe,dump)),"REBUILT_CALLSITE_MISSING")
    need(m[target]["dex"]=="classes.dex","TARGET_MOVED")
    need(m[bridge]["dex"]=="classes.dex","BRIDGE_MOVED")
    need(m[target]["calls"].count(("invoke-static",TRAMPOLINE))==1,
         "PRIMARY_CALLSITE_NOT_EXACT")
    # P40's legacy scanner includes this invocation because the new static
    # signature contains ProcessBuilder as a *parameter*, even though the
    # callee is P47LaunchGate. Require the exact expected single call here.
    need(m[bridge]["calls"]==[("invoke-static",DENY)],
         "BRIDGE_CALLSITE_NOT_EXACT_NO_FALLBACK")
    need(("invoke-virtual",ORIGINAL) not in m[target]["calls"],
         "PRIMARY_STILL_SPAWNS_HOST")
    if os.environ.get("P181_THREE_ORIGINAL_START_DENY")=="1":
        for x in (probe,dump):
            need(m[x]["calls"].count(("invoke-static",TRAMPOLINE))==1
                 and ("invoke-virtual",ORIGINAL) not in m[x]["calls"],
                 "P181_SECONDARY_ORIGINAL_ENGINE_NOT_INTERPOSED")
        need(sum(row["calls"].count(("invoke-virtual",ORIGINAL))
                 for row in m.values())==0,
             "P181_REAL_ENGINE_HOST_DIRECT_START_REMAINS")
    else:
        for x in (probe,dump):
            need(m[x]["calls"].count(("invoke-virtual",ORIGINAL))==1,
                 "NON_TARGET_ORIGINAL_PROBE_CHANGED")
        need(sum(row["calls"].count(("invoke-virtual",ORIGINAL))
                 for row in m.values())==2,"ORIGINAL_HOST_START_COUNT_DRIFT")
    with zipfile.ZipFile(apk) as z:
        main_dex=DEX(z.read("classes.dex"))
        exact_bridge_methods=[
            method for cls in main_dex.get_classes()
            if cls.get_name()==CLASS
            for method in cls.get_methods()
            if method.get_name()=="start"
        ]
        need(len(exact_bridge_methods)==1,"MAIN_DEX_BRIDGE_NOT_UNIQUE")
        bridge_invokes=[
            (inst.get_name(),inst.get_output())
            for _,inst in exact_bridge_methods[0].get_instructions_idx()
            if inst.get_name().startswith("invoke-")
        ]
        need(len(bridge_invokes)==1 and bridge_invokes[0][0]=="invoke-static"
             and DENY in bridge_invokes[0][1],
             "BRIDGE_NOT_EXACTLY_NO_FALLBACK")
        need(not any("Ljava/lang/ProcessBuilder;->start(" in value
                     for _,value in bridge_invokes),"BRIDGE_HOST_START_PRESENT")
        need("classes3.dex" in z.namelist(),"P47_GATE_DEX_MISSING")
        d=DEX(z.read("classes3.dex"))
        classes={c.get_name():c for c in d.get_classes()}
        gate="Lcom/dsh/android/p47/P47LaunchGate;"
        need(gate in classes,"P47_JAVA_GATE_MISSING")
        launch_methods=[method for method in classes[gate].get_methods()
                        if method.get_name()=="startOrDeny"]
        need(len(launch_methods)==1,"GATE_METHOD_NOT_UNIQUE")
        refs=[]
        for _,inst in launch_methods[0].get_instructions_idx():
            if not inst.get_name().startswith("invoke-"):
                continue
            refs.append(inst.get_output())
        need(not any("Ljava/lang/ProcessBuilder;->start(" in i for i in refs),
             "GATE_CALLS_HOST_START")
    print("P47_REBUILT_ORIGINAL_PRIMARY_ENGINE_BRIDGE_NO_HOST_START=PASS")
    if os.environ.get("P181_THREE_ORIGINAL_START_DENY")=="1":
        print("P181_ORIGINAL_V138_THREE_ENGINE_SPAWN_SITES_NO_HOST_EXEC=PASS")
    else:
        print("P47_OTHER_ORIGINAL_PROBEBOOT_AND_DUMPCONFIG_PRESERVED=PASS")
    print("P47_GATE_SOURCE_COMPILED_TO_CLASSES3_DEX=PASS")
    print("P47_ALLOW_PRODUCTION_RELEASE=NO")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=["patch","verify"])
    p.add_argument("target")
    a=p.parse_args()
    patch(a.target) if a.mode=="patch" else verify(a.target)

if __name__=="__main__":
    main()
