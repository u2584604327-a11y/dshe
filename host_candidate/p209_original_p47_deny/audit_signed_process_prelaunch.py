#!/usr/bin/env python3
"""P209 signed-v138 process-field write order and PC250 normal CFG, read-only.

Only SHA-pinned *original* APK DEX is inspected. Never instruments smali,
launches a process, reads cookies, infers runtime register values or releases.
"""
import argparse
from collections import deque
import hashlib
from pathlib import Path
import re
import sys
import zipfile

SIGNED_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
OWNER="Lcom/dsh/android/EngineManager;"
START="Lcom/dsh/android/EngineManager$start$2;"
SET=OWNER+"->access$setProcess$p("
GET=OWNER+"->access$getProcess$p("
SPAWN="Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"

class Denied(Exception):pass
def require(condition,code):
    if not condition:raise Denied("P209_STATIC_PRELAUNCH_DENY_"+code)

def path_avoiding(edges,source,target,forbidden=None):
    """Normal-edge graph only; skip the entire forbidden instruction node."""
    if source==forbidden or target==forbidden:return False
    todo=[source]
    seen=set()
    while todo:
        at=todo.pop()
        if at in seen or at==forbidden:continue
        if at==target:return True
        seen.add(at)
        require(len(seen)<=12000,"UNBOUNDED_CFG_WALK")
        todo.extend(n for n in edges.get(at,()) if n not in seen)
    return False

def split_guards(edges,by_pc,start,end):
    """Potential normal-edge exit guards, NOT observed Android decisions."""
    out=[]
    for pc in sorted(by_pc):
        if not (start<=pc<end and by_pc[pc]["op"].startswith("if-") and
                path_avoiding(edges,start,pc)):
            continue
        successors=edges.get(pc,())
        require(len(successors)==2,"CONDITION_SUCCESSOR_COUNT")
        onward=[path_avoiding(edges,s,end) for s in successors]
        if len(set(onward))>1:
            out.append((pc,by_pc[pc]["op"]))
    return out

def scan_signed(apk):
    from androguard.core.dex import DEX
    import pathlib
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/
                          "p204_oncreate_pc430"))
    import audit_original_oncreate_pc430 as cfg
    source=Path(apk)
    require(source.is_file() and not source.is_symlink(),"PINNED_APK_FILE")
    require(hashlib.sha256(source.read_bytes()).hexdigest()==SIGNED_SHA,
            "PINNED_SIGNED_V138_SHA")
    with zipfile.ZipFile(source) as z:
        require(z.testzip() is None,"ZIP_CRC")
        dexes=sorted(n for n in z.namelist() if
                     re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        require(dexes==["classes.dex","classes2.dex"],"SIGNED_DEX_SET")
        original=[(name,DEX(z.read(name))) for name in dexes]

    field_declarations=[]
    direct_writes=[]
    setters=[]
    getters=[]
    starters=[]
    for dex_name,dex in original:
        for cls in dex.get_classes():
            cname=cls.get_name()
            if cname==OWNER:
                field_declarations.extend((dex_name,fld) for fld in
                    cls.get_fields() if fld.get_name()=="process")
            for method in cls.get_methods():
                if method.get_code() is None:continue
                name=method.get_name()
                if cname==START and name=="invokeSuspend":
                    starters.append(method)
                for pc,inst in method.get_instructions_idx():
                    op,output=inst.get_name(),inst.get_output()
                    if (op.startswith(("iput","sput")) and
                        re.search(re.escape(OWNER)+r"->process(?:[:\s]|$)",
                                  output)):
                        direct_writes.append((dex_name,cname,name,pc,op))
                    if op.startswith("invoke-"):
                        if SET in output:setters.append((dex_name,cname,name,pc))
                        if GET in output:getters.append((dex_name,cname,name,pc))
    require(len(field_declarations)==1 and
            field_declarations[0][0]=="classes.dex",
            "EXACT_ONE_ORIGINAL_PROCESS_FIELD")
    # DEX method metadata, not Android runtime. Bytecode is signed-v138 pinned.
    field=field_declarations[0][1]
    require("".join(field.get_descriptor().split())=="Ljava/lang/Process;",
            "PROCESS_FIELD_TYPE")
    require(len(starters)==1,"EXACT_ORIGINAL_START2_METHOD")
    require(sorted((d,c,n,pc) for d,c,n,pc,_ in direct_writes)==sorted([
        ("classes.dex",OWNER,"access$setProcess$p",0),
        ("classes.dex",OWNER,"stop",74)]),"ORIGINAL_TWO_DIRECT_WRITES_DRIFT")
    require(setters==[("classes.dex",START,"invokeSuspend",3924)],
            "ORIGINAL_ONLY_POSTSPAWN_SET_CALL_DRIFT")
    require(sorted(getters)==sorted([
        ("classes.dex",START,"invokeSuspend",194),
        ("classes.dex",START,"invokeSuspend",4932)]),
        "ORIGINAL_PROCESS_GETTER_CALLS_DRIFT")
    rows=list(starters[0].get_instructions_idx())
    by_ins=dict(rows)
    require(3912 in by_ins and 3924 in by_ins and 202 in by_ins and
            214 in by_ins and 250 in by_ins,
            "ORIGINAL_PC_BOUNDARIES")
    require(by_ins[3912].get_name()=="invoke-virtual" and
            SPAWN in by_ins[3912].get_output() and
            by_ins[3924].get_name().startswith("invoke-") and
            SET in by_ins[3924].get_output(),"SPAWN_AND_SET_BOUNDARY")
    for pc,op in ((202,"if-eqz"),(214,"if-ne")):
        ins=by_ins[pc]
        require(ins.get_name()==op and
                pc+2*ins.get_ref_off()==250,
                "ORIGINAL_PROCESS_GUARD_TARGET_"+str(pc))
    nodes=[cfg.instruction(pc,ins.get_name(),ins.get_length(),
        ins.get_ref_off() if
        cfg.is_cond(ins.get_name()) or cfg.is_jump(ins.get_name())
        else None) for pc,ins in rows]
    edges,unknown,by_pc=cfg.graph(nodes)
    require(len(unknown)==0,"UNEXPANDED_ORIGINAL_SWITCH_OR_PAYLOAD")
    require(path_avoiding(edges,0,3924),"ORIGINAL_SET_NOT_REACHABLE")
    bypass=path_avoiding(edges,0,3924,forbidden=3912)
    after_null=path_avoiding(edges,250,3912)
    candidates=split_guards(edges,by_pc,250,3912)
    require(len(candidates)<=80,"POSTNULL_SPLIT_GUARDS_BOUND")
    print("P209_SIGNED_PROCESS_FIELD_EXACT_TYPE_AND_UNIQUE=PASS")
    print("P209_SIGNED_PROCESS_DIRECT_WRITERS=ACCESSOR_AND_STOP_ONLY")
    print("P209_SIGNED_START2_PROCESS_SETTER_CALLSITE=PC3924_AFTER_PC3912")
    print("P209_SIGNED_START2_PROCESS_GETTER_CALLS=PC194_AND_PC4932")
    print("P209_SIGNED_PROCESS_GUARD_202_NULL_TAKEN_PC250=PASS")
    print("P209_SIGNED_PROCESS_GUARD_214_COMPARE_TAKEN_PC250=PASS")
    print("P209_SIGNED_SETTER_PC3924_NORMAL_PATH_BYPASS_PC3912="+
          ("POSSIBLE" if bypass else "NOT_FOUND_IN_MODELED_CFG"))
    print("P209_SIGNED_PC250_TO_PC3912_NORMAL_CFG="+
          ("REACHABLE" if after_null else "NOT_PROVEN_REACHABLE"))
    print("P209_SIGNED_PC250_PC3912_SPLIT_GUARD_COUNT="+str(len(candidates)))
    for pc,op in candidates[:12]:
        print("P209_SIGNED_PC250_POTENTIAL_BYPASS_GUARD_PC="+str(pc)+
              ",OP="+op)
    print("P209_SIGNED_PROCESS_FIRST_START_FIELD_DEFAULT="+
          "NULL_IF_FRESH_INSTANCE_AND_NO_UNMODELED_WRITER")
    print("P209_SIGNED_PROCESS_REFLECTION_NATIVE_AND_EXCEPTION_EDGES=NOT_AUDITED")
    print("P209_SIGNED_PROCESS_ANDROID_RUNTIME_NULLNESS=NOT_ATTESTED")
    print("P209_ORIGINAL_PC250_OR_PC3912_ACTUALLY_EXECUTED=NOT_ATTESTED")
    print("P209_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P209_SIGNED_PROCESS_PRELAUNCH_READONLY_AUDIT=PASS")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("signed_original_v138")
    args=parser.parse_args()
    try:scan_signed(args.signed_original_v138)
    except Denied as ex:
        print(str(ex),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_STATIC_PRELAUNCH_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
