#!/usr/bin/env python3
"""P241 bounded read-only signed-v138 normal-CFG receiver alias investigation.

Only a NORMAL-CFG register candidate; exception handler edges, resume states,
runtime branch choices and reflective state are never proven by this report.
No DEX edit, instrumented branch, raw register, field or user data output.
"""
import argparse
from collections import deque
import re
import sys
from pathlib import Path

from p238_signed_coroutine_capture import (
    START, ENGINE, DESC, SIGNED_SHA, Denied, require
)

MAX_PCS=12000
MAX_REGS=512
MAX_WORK=70000
ALIAS="A"
OTHER="N"
UNKNOWN="U"

def parse_two(output):
    t="".join(output.split())
    m=re.fullmatch(r"v([0-9]+),v([0-9]+)",t)
    return (int(m.group(1)),int(m.group(2))) if m else None

def parse_dest(output):
    t="".join(output.split())
    m=re.match(r"^v([0-9]+)(?:,|$)",t)
    return int(m.group(1)) if m else None

def merge(a,b):
    return tuple(a[i]|b[i] for i in range(len(a)))

def transfer(op,output,state):
    s=list(state)
    incomplete=False
    if op.startswith("move-object"):
        reg=parse_two(output)
        if reg and all(0<=x<len(s) for x in reg):
            s[reg[0]]=s[reg[1]]
        else:
            s=[frozenset({UNKNOWN}) for _ in s]
            incomplete=True
    elif op=="check-cast" or op=="nop" or op.startswith(("if-","goto","invoke-","return")) or op in ("throw","monitor-enter","monitor-exit"):
        pass
    elif op.startswith(("move-wide","move/from","move/16")):
        # Unknown wide pairs can clobber two registers: invalidate all.
        s=[frozenset({UNKNOWN}) for _ in s]
        incomplete=True
    elif op.startswith(("move","const","new-","sget","iget","aget","instance-of",
                        "array-length","cmp","neg","not","add","sub","mul","div",
                        "rem","rsub","and","or","xor","shl","shr","ushr",
                        "int-to","long-to","float-to","double-to")):
        dest=parse_dest(output)
        if dest is None or not 0<=dest<len(s):
            s=[frozenset({UNKNOWN}) for _ in s]
            incomplete=True
        else:
            # Other instructions create or load values with no proven p0 alias.
            # "unknown" can include p0 and must NOT establish an alias.
            s[dest]=frozenset({UNKNOWN})
    elif op.startswith(("iput","sput","aput")):
        # Field or array writes do not reassign the register operand.
        pass
    else:
        s=[frozenset({UNKNOWN}) for _ in s]
        incomplete=True
    return tuple(s),incomplete

def normal_alias(rows,edges,receiver,source,target=190,register_count=None):
    """Finite monotone abstract interpretation on target-reaching normal edges."""
    require(0 in rows and target in rows,"P241_PC_SET")
    require(0<=receiver<MAX_REGS and 0<=source<MAX_REGS,"P241_REG_BOUND")
    require(receiver!=source,"P241_EXPECT_PC190_NON_P0_SOURCE")
    require(len(rows)<=MAX_PCS,"P241_METHOD_PC_BOUND")
    reverse={pc:[] for pc in rows}
    for pc,dests in edges.items():
        require(pc in rows,"P241_UNKNOWN_SOURCE_PC")
        for d in dests:
            require(d in rows,"P241_UNKNOWN_DEST_PC")
            reverse[d].append(pc)
    relevant={target}
    todo=[target]
    while todo:
        for p in reverse[todo.pop()]:
            if p not in relevant:
                relevant.add(p);todo.append(p)
    if 0 not in relevant:
        return "NOT_ATTESTED",False,0
    # A valid alias can pass through a third v-register. A state vector
    # sized only for the endpoint silently drops such intermediate copies.
    # For signed DEX, enforce the exact code-item register count.
    inferred=max(receiver,source)+1
    for op,output in rows.values():
        if op.startswith("move-object"):
            pair=parse_two(output)
            if pair is not None:
                inferred=max(inferred,pair[0]+1,pair[1]+1)
    count=inferred if register_count is None else register_count
    require(type(count) is int and inferred<=count<=MAX_REGS,
            "P241_REG_COUNT")
    initial=tuple(frozenset({ALIAS}) if i==receiver else
                  frozenset({UNKNOWN}) for i in range(count))
    incoming={0:initial}
    q=deque([0]);iterations=0;incomplete=False
    while q:
        iterations+=1
        require(iterations<=MAX_WORK,"P241_DATAFLOW_BOUND")
        pc=q.popleft()
        if pc==target:continue
        op,output=rows[pc]
        s,unknown_step=transfer(op,output,incoming[pc])
        incomplete |= unknown_step
        for next_pc in edges.get(pc,()):
            if next_pc not in relevant:continue
            old=incoming.get(next_pc)
            updated=s if old is None else merge(old,s)
            if old != updated:
                incoming[next_pc]=updated
                q.append(next_pc)
    if target not in incoming:
        return "NOT_ATTESTED",incomplete,iterations
    state=incoming[target][source]
    if state==frozenset({ALIAS}) and not incomplete:
        answer="ALL_NORMAL_PATHS"
    elif ALIAS in state:
        answer="MIXED_NORMAL_PATHS"
    else:
        answer="NOT_ATTESTED"
    return answer,incomplete,iterations

def try_span_verdict(try_items, total_code_units):
    """P242: try_item start/length are 16-bit DEX code units, PCs are bytes.

    Classify overlapping byte ranges only. Handler target edges and coroutine
    resume paths are not modeled; no all-path alias claim is possible here.
    """
    require(type(total_code_units) is int and 0<total_code_units<=200000,
            "P242_METHOD_SIZE_BOUND")
    require(len(try_items)<=4096,"P242_TRY_ITEMS_BOUND")
    intervals=[]
    for start,count in try_items:
        require(type(start) is int and type(count) is int and
                0<=start<total_code_units and 0<count<=65535 and
                start+count<=total_code_units,"P242_TRY_RANGE_BOUNDS")
        intervals.append((2*start,2*(start+count)))
    intervals.sort()
    require(all(intervals[i-1][1]<=intervals[i][0]
                for i in range(1,len(intervals))),"P242_OVERLAPPING_TRY_ITEMS")
    covers=lambda pc:any(a<=pc<b for a,b in intervals)
    overlaps=lambda lo,hi:any(a<hi and lo<b for a,b in intervals)
    return (
        "YES" if covers(176) else "NO",
        "YES" if overlaps(182,190) else "NO",
        "YES" if covers(190) else "NO",
        "YES" if overlaps(0,190) else "NO"
    )

def audit(original):
    import hashlib,zipfile
    from androguard.core.dex import DEX
    from p238_signed_coroutine_capture import operand_shape
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/"p204_oncreate_pc430"))
    import audit_original_oncreate_pc430 as cfg
    p=Path(original)
    require(p.is_file() and not p.is_symlink(),"P241_ORIGINAL_FILE")
    require(hashlib.sha256(p.read_bytes()).hexdigest()==SIGNED_SHA,"P241_ORIGINAL_SHA")
    with zipfile.ZipFile(p) as z:
        require(z.testzip() is None,"P241_ORIGINAL_ZIP")
        names=sorted(n for n in z.namelist() if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        require(names==["classes.dex","classes2.dex"],"P241_DEX_SET")
        dex=DEX(z.read("classes.dex"))
    classes=[c for c in dex.get_classes() if c.get_name()==START]
    require(len(classes)==1,"P241_START_CLASS")
    methods=[m for m in classes[0].get_methods()
             if m.get_name()=="invokeSuspend" and
             "".join(m.get_descriptor().split())==DESC]
    require(len(methods)==1,"P241_START_METHOD")
    method=methods[0]
    code=method.get_code()
    require(code is not None and code.get_ins_size()==2,"P241_RECEIVER_SIGNATURE")
    receiver=code.get_registers_size()-code.get_ins_size()
    require(0<=receiver<MAX_REGS,"P241_RECEIVER_RANGE")
    rows=list(method.get_instructions_idx())
    by_pc=dict(rows)
    require(len(rows)==len(by_pc) and all(pc in by_pc for pc in (0,176,182,190,194,202,214,250,3912)),
            "P241_ORIGINAL_ANCHORS")
    target=by_pc[190]
    require(target.get_name()=="iget-object","P241_TARGET_OPCODE")
    owner,kind,category=operand_shape(target.get_output(),receiver)
    require(owner=="COROUTINE" and kind=="ENGINE" and category=="OTHER_VREG",
            "P241_PC190_EXPECTED_OPERAND")
    clean="".join(target.get_output().split())
    match=re.match(r"^v[0-9]+,v([0-9]+),"+re.escape(START)+r"->",clean)
    require(match is not None,"P241_SOURCE_SHAPE")
    source=int(match.group(1))
    require(source<MAX_REGS,"P241_SOURCE_BOUND")
    nodes=[cfg.instruction(pc,ins.get_name(),ins.get_length(),
                           ins.get_ref_off() if cfg.is_cond(ins.get_name())
                           or cfg.is_jump(ins.get_name()) else None)
           for pc,ins in rows]
    edges,unknown,by=cfg.graph(nodes)
    safe_rows={pc:(ins.get_name(),ins.get_output()) for pc,ins in rows}
    answer,incomplete,visited=normal_alias(
        safe_rows,edges,receiver,source,register_count=code.get_registers_size())
    if unknown:
        # An unexpanded switch/payload can hide a predecessor to PC190;
        # normal-path ALL is not a complete normal CFG proof in that case.
        answer="NOT_ATTESTED"
    handlers=code.get_tries_size()
    require(type(handlers) is int and 0<=handlers<=4096,"P241_TRY_TABLE")
    items=list(code.get_tries() or [])
    require(len(items)==handlers,"P242_TRY_TABLE_COUNT")
    intervals=[(item.get_start_addr(),item.get_insn_count()) for item in items]
    c176,c182_190,c190,c0_190=try_span_verdict(
        intervals,code.get_insns_size())
    print("P241_SIGNED_SHA_AND_ORIGINAL_PC190_OPERAND=PASS")
    print("P241_PC190_NORMAL_CFG_SOURCE_ALIAS="+answer)
    print("P241_NORMAL_CFG_INCOMPLETE_OPCODE="+("YES" if incomplete else "NO"))
    print("P241_SWITCH_OR_PAYLOAD_UNMODELED="+("YES" if unknown else "NO"))
    print("P241_EXCEPTION_HANDLERS="+("PRESENT" if handlers else "NONE"))
    print("P242_PC176_IN_TRY_REGION="+c176)
    print("P242_PC182_TO_PC190_TRY_OVERLAP="+c182_190)
    print("P242_PC190_IN_TRY_REGION="+c190)
    print("P242_PRE_PC190_ANY_TRY_REGION="+c0_190)
    print("P242_EXCEPTION_HANDLER_TARGET_EDGES=NOT_MODELED")
    print("P242_ALL_PATH_ALIAS_WITH_EXCEPTIONS=NOT_ATTESTED")
    print("P242_TRY_RANGES_CODEUNIT_TO_BYTE_PC=PASS")
    print("P241_REG_ALIAS_EXCEPTION_SUSPENSION_AND_RUNTIME=NOT_ATTESTED")
    print("P241_ORIGINAL_PC202_PC214_DYNAMIC_BRANCH=NOT_ATTESTED")
    print("P241_SIGNED_ORIGINAL_DEX_AND_USER_DATA_EDITED=NO")
    print("P241_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P241_ORIGINAL_PC190_RECEIVER_LOCAL_CFG_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("original_signed_v138")
    args=p.parse_args()
    try:audit(args.original_signed_v138)
    except Denied as e:
        print(str(e));return 2
    except Exception:
        print("P241_SIGNED_LOCAL_CFG_DENY_UNEXPECTED");return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
