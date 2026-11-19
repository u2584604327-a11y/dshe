#!/usr/bin/env python3
"""P219: read-only SHA-pinned original start$2 PC182-PC406/PC414 normal CFG.

No DEX patch, no Android permission change, no process launch. Only static
normal edges are modeled; exceptions, coroutine suspension and runtime values
are NOT attested. Never print original operands, permissions or user data.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile
from audit_signed_node_bootstrap import SIGNED_SHA, START, Denied, need
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"p204_oncreate_pc430"))
import audit_original_oncreate_pc430 as cfg

DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
REQUIRED=(176,182,406,412,414,418,3912)

def reach(edges, start, target, excluded=None):
    if start == excluded or target == excluded: return False
    pending=[start]
    visited=set()
    while pending:
        pc=pending.pop()
        if pc == excluded or pc in visited: continue
        if pc == target: return True
        visited.add(pc)
        need(len(visited)<=12000,"P219_WALK_BOUND")
        pending.extend(n for n in edges.get(pc,()) if n not in visited)
    return False

def summarize(edges,by_pc):
    need(all(pc in by_pc for pc in REQUIRED[1:]),"P219_PCS_REQUIRED")
    need(by_pc[414]["op"]=="if-ne","P219_PC414_OPCODE_DRIFT")
    need(len(edges.get(414,()))==2 and set(edges[414])=={172,418},
         "P219_PC414_SUCCESSOR_DRIFT")
    need(by_pc[418]["op"]=="return-object" and not edges.get(418),
         "P219_PC418_TERMINAL_RETURN_DRIFT")
    early=[pc for pc,row in sorted(by_pc.items())
           if row["op"].startswith("return") and reach(edges,182,pc,excluded=406)]
    splits=[]
    for pc,row in sorted(by_pc.items()):
        if not row["op"].startswith("if-"): continue
        if not reach(edges,182,pc,excluded=406): continue
        succ=edges.get(pc,())
        need(len(succ)==2 and len(set(succ))==2,"P219_SPLIT_SUCCESSOR_DRIFT")
        possibilities=[reach(edges,d,406) for d in succ]
        if possibilities[0]!=possibilities[1]: splits.append(pc)
    need(len(splits)<=120,"P219_SPLIT_COUNT_BOUND")
    return {
        "p182_reaches_406":reach(edges,182,406),
        "early_returns":early,
        "split_guards":splits,
        "taken_reaches_3912":reach(edges,172,3912),
        "fall_reaches_3912":reach(edges,418,3912)
    }

def audit(apk):
    from androguard.core.dex import DEX
    path=Path(apk)
    need(path.is_file() and not path.is_symlink(),"P219_SIGNED_APK_FILE")
    need(hashlib.sha256(path.read_bytes()).hexdigest()==SIGNED_SHA,
         "P219_SIGNED_SHA_DRIFT")
    with zipfile.ZipFile(path) as z:
        need(z.testzip() is None,"P219_ORIGINAL_ZIP_CRC")
        names=sorted(n for n in z.namelist()
                     if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(names==["classes.dex","classes2.dex"],"P219_TWO_SIGNED_DEX")
        dex=DEX(z.read("classes.dex"))
    methods=[m for cls in dex.get_classes() if cls.get_name()==START
             for m in cls.get_methods() if m.get_name()=="invokeSuspend"
             and "".join(m.get_descriptor().split())==DESC]
    need(len(methods)==1 and methods[0].get_code() is not None,
         "P219_UNIQUE_START2")
    method=methods[0]
    rows=list(method.get_instructions_idx())
    ins=dict(rows)
    need(all(pc in ins for pc in REQUIRED),"P219_REQUIRED_PC_BOUNDARIES")
    norm=lambda pc:"".join(ins[pc].get_output().split())
    need(ins[176].get_name()=="invoke-static/range"
         and "Lkotlin/ResultKt;->throwOnFailure(" in norm(176)
         and 176+ins[176].get_length()==182
         and ins[182].get_name()=="iget-object",
         "P219_PC176_182_DRIFT")
    need(ins[406].get_name()=="invoke-virtual"
         and "Lcom/dsh/android/termux/TermuxBootstrap;->installNodeRuntime(" in norm(406)
         and 406+ins[406].get_length()==412
         and ins[412].get_name()=="move-result-object"
         and 412+ins[412].get_length()==414,
         "P219_PC406_414_DRIFT")
    need(ins[3912].get_name()=="invoke-virtual"
         and "Ljava/lang/ProcessBuilder;->start()" in norm(3912),
         "P219_PC3912_DRIFT")
    nodes=[cfg.instruction(pc,x.get_name(),x.get_length(),
             x.get_ref_off() if cfg.is_cond(x.get_name()) or
             cfg.is_jump(x.get_name()) else None) for pc,x in rows]
    edges,unknown,by_pc=cfg.graph(nodes)
    need(not unknown,"P219_UNKNOWN_SWITCH_OR_PAYLOAD")
    s=summarize(edges,by_pc)
    print("P219_ORIGINAL_SIGNED_V138_SHA_AND_DEX=PASS")
    print("P219_PC176_182_406_412_414_418_3912_ANCHORS=PASS")
    print("P219_PC182_TO_PC406_NORMAL_CFG="+
          ("REACHABLE" if s["p182_reaches_406"] else "NOT_REACHABLE"))
    print("P219_EARLY_RETURNS_BYPASS_PC406_COUNT="+str(len(s["early_returns"])))
    for pc in s["early_returns"][:12]:
        print("P219_EARLY_RETURN_PC="+str(pc))
    print("P219_SPLIT_GUARDS_PC182_TO_PC406_COUNT="+str(len(s["split_guards"])))
    for pc in s["split_guards"][:12]:
        print("P219_SPLIT_GUARD_PC="+str(pc))
    print("P219_PC414_TAKEN_PC=172")
    print("P219_PC414_FALL_PC=418")
    print("P219_PC414_TAKEN_TO_PC3912_NORMAL_CFG="+
          ("REACHABLE" if s["taken_reaches_3912"] else "NOT_REACHABLE"))
    print("P219_PC414_FALL_TO_PC3912_NORMAL_CFG="+
          ("REACHABLE" if s["fall_reaches_3912"] else "NOT_REACHABLE"))
    print("P219_ORIGINAL_TRY_REGION_COUNT="+str(len(method.get_code().get_tries() or [])))
    print("P219_EXCEPTION_SUSPENSION_AND_REGISTER_VALUES=NOT_ATTESTED")
    print("P219_PC406_PC414_REAL_ANDROID_EXECUTION=NOT_ATTESTED")
    print("P219_ORIGINAL_APK_USER_DATA_MODIFICATION=NO")
    print("P219_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P219_SIGNED_ORIGINAL_START_CFG_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    a=p.parse_args()
    try: audit(a.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P219_FAIL_CLOSED_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
