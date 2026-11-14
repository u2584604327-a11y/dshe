#!/usr/bin/env python3
"""P243: read-only, SHA-pinned DEX try/handler-entry reachability to PC190.

AOSP DEX: try start/count and catch handler addresses use 16-bit code units,
handler_off is BYTE offset from encoded_catch_handler_list. Convert to byte
PCs only when constructing the original normal/exception CFG.
Never patch original or derived DEX. No raw methods/registers/handler PCs.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from p238_signed_coroutine_capture import START, DESC, SIGNED_SHA, Denied, require
from p241_signed_pc190_receiver_alias import MAX_PCS, normal_alias, try_span_verdict
from p238_signed_coroutine_capture import operand_shape

MAX_TRIES = 4096
MAX_HANDLERS = 4096
MAX_EDGES = 180000
MAX_UNITS = 200000

def exception_edges(rows, try_items, handlers, total_units):
    """Build conservative protected-PC -> every associated handler edge.

    rows: dict bytePC -> (opcode, operands); tries: (startUnit, countUnit,
    handler_offset) tuples; handlers: offset -> tuple(catchEntryUnit...).
    Unknown handler address, codeunit boundary or overlapping range denies.
    """
    require(type(total_units) is int and 0<total_units<=MAX_UNITS,
            "P243_CODE_UNITS")
    require(0 < len(rows) <= MAX_PCS and 190 in rows, "P243_PC_ROWS")
    require(0<len(try_items)<=MAX_TRIES and 0<len(handlers)<=MAX_HANDLERS,
            "P243_TRY_AND_HANDLER_COUNTS")
    require(all(type(pc) is int and 0<=pc<2*total_units and pc%2==0
                for pc in rows), "P243_PC_ALIGNMENT")
    pcset=set(rows)
    intervals=[]
    edges={pc:set() for pc in rows}
    targets=set()
    for start,count,off in try_items:
        require(all(type(v) is int for v in (start,count,off)) and
                0<=start<total_units and 0<count<=65535 and
                start+count<=total_units and off in handlers,
                "P243_TRY_ITEM_AND_HANDLER_OFFSET")
        lo,hi=2*start,2*(start+count)
        require(lo in pcset and (hi==2*total_units or hi in pcset),
                "P243_TRY_INSTRUCTION_BOUNDARY")
        intervals.append((lo,hi,off))
    intervals.sort()
    require(all(intervals[i-1][1]<=intervals[i][0]
                for i in range(1,len(intervals))),
            "P243_TRY_OVERLAP")
    targets_by_offset={}
    for off,units in handlers.items():
        require(type(off) is int and off>=0 and
                isinstance(units,tuple) and 0<len(units)<=MAX_HANDLERS,
                "P243_HANDLER_ENTRY_FORMAT")
        if off not in {r[2] for r in intervals}:
            # Orphan handler definitions may be legal; do not use them as
            # control-flow roots because no try_item can dispatch to them.
            continue
        dests=[]
        for unit in units:
            require(type(unit) is int and 0<=unit<total_units and
                    2*unit in pcset, "P243_HANDLER_ENTRY_BOUNDARY")
            dests.append(2*unit)
            targets.add(2*unit)
        targets_by_offset[off]=frozenset(dests)
    require(targets and len(targets)<=MAX_HANDLERS,"P243_NO_HANDLER_TARGET")
    total_edges=0
    for lo,hi,off in intervals:
        for pc in pcset:
            if lo<=pc<hi:
                adds=targets_by_offset[off]
                edges[pc].update(adds)
                total_edges+=len(adds)
                require(total_edges<=MAX_EDGES, "P243_EDGE_CAP")
    return {pc:tuple(sorted(eds)) for pc,eds in edges.items()}, frozenset(targets)

def any_handler_reaches_target(normal_edges,exceptional,handler_targets,target=190):
    """Conservative union-graph walk, including chained exceptional jumps."""
    require(target in normal_edges and target in exceptional,
            "P243_TARGET_MISSING")
    allpcs=set(normal_edges)
    require(all(set(dests).issubset(allpcs) for dests in normal_edges.values())
            and all(set(dests).issubset(allpcs) for dests in exceptional.values())
            and all(t in allpcs for t in handler_targets),"P243_UNKNOWN_PC")
    pending=list(handler_targets)
    visited=set()
    while pending:
        pc=pending.pop()
        if pc in visited:continue
        visited.add(pc)
        require(len(visited)<=MAX_PCS,"P243_WALK_BOUND")
        if pc==target:return "YES"
        pending.extend(normal_edges.get(pc,()))
        pending.extend(exceptional.get(pc,()))
    return "NO"

def handler_definitions(code):
    """Extract Androguard 4.1.3 encoded handlers without printing raw data."""
    table=code.get_handlers()
    require(table is not None and table.get_size()>0 and
            table.get_size()<=MAX_HANDLERS, "P243_HANDLER_LIST")
    origin=table.get_off()  # absolute file byte offset of handler_list
    result={}
    for entry in table.get_list():
        off=entry.get_off()-origin  # try_item.handler_off uses bytes!
        require(type(off) is int and off>=1 and off not in result,
                "P243_HANDLER_OFFSET_DUPLICATE")
        units=[pair.get_addr() for pair in entry.get_handlers()]
        if entry.get_size()<=0:
            units.append(entry.get_catch_all_addr())
        require(0<len(units)<=MAX_HANDLERS, "P243_EMPTY_HANDLER")
        result[off]=tuple(units)
    require(len(result)==table.get_size(), "P243_LIST_MISMATCH")
    return result

def audit(apk):
    from androguard.core.dex import DEX
    root=Path(__file__).resolve().parents[1]
    sys.path.insert(0,str(root/"p204_oncreate_pc430"))
    import audit_original_oncreate_pc430 as cfg
    p=Path(apk)
    require(p.is_file() and not p.is_symlink(),"P243_ORIGINAL_FILE")
    require(hashlib.sha256(p.read_bytes()).hexdigest()==SIGNED_SHA,
            "P243_SIGNED_ORIGINAL_SHA")
    with zipfile.ZipFile(p) as z:
        require(z.testzip() is None,"P243_ZIP_CRC")
        names=sorted(n for n in z.namelist()
                     if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        require(names==["classes.dex","classes2.dex"],"P243_DEX_SET")
        dex=DEX(z.read("classes.dex"))
    methods=[m for c in dex.get_classes() if c.get_name()==START
             for m in c.get_methods() if m.get_name()=="invokeSuspend"
             and "".join(m.get_descriptor().split())==DESC]
    require(len(methods)==1 and methods[0].get_code() is not None,
            "P243_UNIQUE_ORIGINAL_METHOD")
    m=methods[0]
    code=m.get_code()
    rows=list(m.get_instructions_idx())
    pcs=dict(rows)
    require(len(rows)==len(pcs) and all(pc in pcs for pc in
             (0,176,182,190,194,202,214,250,3912)),
            "P243_ORIGINAL_PC_ANCHORS")
    receiver=code.get_registers_size()-code.get_ins_size()
    owner,kind,srckind=operand_shape(pcs[190].get_output(),receiver)
    require(pcs[190].get_name()=="iget-object" and owner=="COROUTINE"
            and kind=="ENGINE" and srckind=="OTHER_VREG",
            "P243_PC190_SOURCE_SHAPE")
    match=re.match(r"^v[0-9]+,v([0-9]+),",
                  "".join(pcs[190].get_output().split()))
    require(match is not None,"P243_TARGET_SOURCE_REGISTER")
    source=int(match.group(1))
    nodes=[cfg.instruction(pc,x.get_name(),x.get_length(),
           x.get_ref_off() if cfg.is_cond(x.get_name()) or
           cfg.is_jump(x.get_name()) else None) for pc,x in rows]
    normal_edges,unknown,_=cfg.graph(nodes)
    require(not unknown,"P243_UNKNOWN_SWITCH_OR_PAYLOAD")
    safe_rows={pc:(x.get_name(),x.get_output()) for pc,x in rows}
    normal,incomplete,_=normal_alias(
        safe_rows,normal_edges,receiver,source,
        register_count=code.get_registers_size())
    require(code.get_tries_size()>0,"P243_EXPECT_ORIGINAL_TRIES")
    tries=[(x.get_start_addr(),x.get_insn_count(),x.get_handler_off())
           for x in (code.get_tries() or [])]
    require(len(tries)==code.get_tries_size(),"P243_TRY_COUNT_DRIFT")
    spans=try_span_verdict(
        [(a,b) for a,b,_ in tries],code.get_insns_size())
    require(spans==("NO","NO","NO","NO"),
            "P243_SIGNED_PRE_PC190_PROTECTION_DRIFT")
    exceptional,targets=exception_edges(
        safe_rows,tries,handler_definitions(code),code.get_insns_size())
    can_return=any_handler_reaches_target(normal_edges,exceptional,targets)
    # No inference about direct asynchronous resume or runtime registers.
    whole=("ALL_MODELED_STATIC_EDGES" if can_return=="NO" and
           normal=="ALL_NORMAL_PATHS" and not incomplete
           else "NOT_ATTESTED")
    print("P243_SIGNED_V138_SHA_AND_HANDLER_BYTES=PASS")
    print("P243_HANDLER_OFF_BYTE_RELATIVE_BASE=VERIFIED")
    print("P243_HANDLER_TARGET_CODEUNIT_CONVERSION=PASS")
    print("P243_EXCEPTION_EDGES_BOUNDED=PASS")
    print("P243_HANDLER_TO_PC190_REACHABLE="+can_return)
    print("P243_PC190_ALIAS_INCLUDING_HANDLER_EDGES="+whole)
    print("P243_COROUTINE_RESUME_EXCEPTION_RUNTIME=NOT_ATTESTED")
    print("P243_PC202_PC214_DYNAMIC_BRANCH=NOT_ATTESTED")
    print("P243_SIGNED_APK_DEX_AND_USER_DATA_MODIFIED=NO")
    print("P243_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P243_SIGNED_EXCEPTION_ENTRY_CFG_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("original_signed_v138")
    args=p.parse_args()
    try:audit(args.original_signed_v138)
    except Denied as e:
        print(str(e))
        return 2
    except Exception:
        print("P243_SIGNED_EXCEPTION_CFG_DENY_UNEXPECTED")
        return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
