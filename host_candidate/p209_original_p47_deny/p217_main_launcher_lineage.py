#!/usr/bin/env python3
"""P217: bounded, read-only local Dalvik register lineage for MainActivity launchers.

The original signed APK is SHA256-pinned and scanned only in memory. No method,
permission literal, launcher field name, DEX operand, or user data is printed.
A linear register witness does NOT prove inter-basic-block reaching definitions,
runtime permission dispatch, or causality of the P209 PC3912 failure.
"""
import argparse
from collections import defaultdict
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import Denied, SIGNED_SHA, need
from p216_activity_result_contracts import (
    MAIN, LAUNCHER, launcher_fields, event_for,
)

REG = re.compile(r"v[0-9]{1,5}")
REGISTER_RET = ")Landroidx/activity/result/ActivityResultLauncher;"
REG_LIMIT = 2048
METHOD_LIMIT = 100000
ROWS_LIMIT = 50000

def operand_regs(ins):
    """Accept explicit Dalvik registers only; refuse /range and malformed operands."""
    output = ins.get_output()
    prefix = output.split("L", 1)[0].strip().strip(",")
    if not prefix or ".." in prefix or "{" in prefix or "}" in prefix:
        return ()
    parts = [p.strip() for p in prefix.split(",")]
    if len(parts) > 8 or any(REG.fullmatch(p) is None for p in parts):
        return ()
    return tuple(parts)

def _put(states, dest, source):
    if dest is None:
        states.clear()
    elif source is None:
        states.pop(dest, None)
    else:
        states[dest] = source
    need(len(states) <= REG_LIMIT, "P217_REGISTER_STATE_BOUND")

def _result_contract(ins, registers, states, fields):
    event = event_for(ins, fields)
    if event != ("ACTIVITY_RESULT_REGISTER", "REGISTRATION"):
        return None
    if not ins.get_name().startswith(("invoke-virtual", "invoke-interface", "invoke-super")):
        return None
    if REGISTER_RET not in ins.get_output() or len(registers) < 3:
        return None
    contract = states.get(registers[1])
    if contract is None or contract[0] != "READY_CONTRACT":
        return None
    return ("REGISTERED_LAUNCHER", contract[1])

def trace_method(rows, fields):
    """Sequential witness, resetting on branches/unknown writes. No CFG claim."""
    states = {}
    pending = None
    field_assignments = []
    launches = []
    need(len(rows) <= ROWS_LIMIT, "P217_METHOD_INSTRUCTION_BOUND")
    for pc, ins in rows:
        op = ins.get_name()
        regs = operand_regs(ins)
        event = event_for(ins, fields)
        old_pending, pending = pending, None
        if op.startswith(("if-", "goto", "packed-switch", "sparse-switch")) or op in (
                "throw", "monitor-enter", "monitor-exit"):
            states.clear()
            continue
        if op.startswith("return"):
            states.clear()
            continue
        if op == "new-instance":
            subtype = event[1] if event and event[0] in (
                "PERMISSION_CONTRACT_NEW", "OTHER_CONTRACT_NEW") else None
            _put(states, regs[0] if len(regs) == 1 else None,
                 ("NEW_CONTRACT", subtype) if subtype else None)
            continue
        if op == "move-result-object":
            _put(states, regs[0] if len(regs) == 1 else None, old_pending)
            continue
        if op.startswith("move-object"):
            _put(states, regs[0] if len(regs) == 2 else None,
                 states.get(regs[1]) if len(regs) == 2 else None)
            continue
        if op == "check-cast" or op == "nop":
            continue
        if op == "iget-object":
            if event and event[0] == "LAUNCHER_FIELD_GET" and len(regs) == 2:
                _put(states, regs[0], ("LAUNCHER_FIELD", event[1]))
            else:
                _put(states, regs[0] if regs else None, None)
            continue
        if op == "iput-object":
            if event and event[0] == "LAUNCHER_FIELD_SET" and len(regs) == 2:
                src = states.get(regs[0])
                kind = src[1] if src and src[0] == "REGISTERED_LAUNCHER" else "UNKNOWN"
                field_assignments.append((event[1], kind))
            continue
        if op.startswith("invoke-"):
            if event and event[0] == "CONTRACT_CONSTRUCTOR_INVOKE":
                if len(regs) >= 1:
                    src = states.get(regs[0])
                    if src == ("NEW_CONTRACT", event[1]):
                        states[regs[0]] = ("READY_CONTRACT", event[1])
                    else:
                        states.pop(regs[0], None)
            elif event and event[0] == "ACTIVITY_RESULT_REGISTER":
                pending = _result_contract(ins, regs, states, fields)
            elif event and event[0] == "GENERIC_LAUNCH":
                src = states.get(regs[0]) if regs else None
                field = src[1] if src and src[0] == "LAUNCHER_FIELD" else None
                launches.append((pc, field))
            continue
        # Unknown or write-producing opcode: never preserve an unproven alias.
        if op.startswith((
                "const", "move", "new-", "sget", "iget", "aget", "instance-of",
                "array-length", "cmp", "add", "sub", "mul", "div", "rem",
                "and", "or", "xor", "shl", "shr", "ushr", "neg", "not",
                "int-to", "long-to", "float-to", "double-to", "filled-new-array",
                "rsub", "aget-wide")):
            _put(states, regs[0] if regs else None, None)
        elif op.startswith(("iput", "sput", "aput")):
            continue
        else:
            states.clear()
    return field_assignments, launches

def inspect_dexes(dexes):
    mains = [cls for _, dex in dexes for cls in dex.get_classes()
             if cls.get_name() == MAIN]
    need(len(mains) == 1, "P217_ONE_MAIN_ACTIVITY")
    fields = launcher_fields(mains[0])
    need(len(fields) == 4, "P217_FOUR_TYPED_LAUNCHER_FIELDS")
    assignments = defaultdict(set)
    launches = []
    scanned = 0
    for _, dex in dexes:
        for cls in dex.get_classes():
            for method in cls.get_methods():
                if method.get_code() is None:
                    continue
                scanned += 1
                need(scanned <= METHOD_LIMIT, "P217_METHOD_BOUND")
                if cls.get_name() != MAIN:
                    continue
                rows = list(method.get_instructions_idx())
                local_assignments, local_launches = trace_method(rows, fields)
                for field, kind in local_assignments:
                    assignments[field].add(kind)
                launches.extend(local_launches)
    need(len(launches) == 4, "P217_FOUR_MAIN_GENERIC_LAUNCHES")
    labels = {}
    for field in fields.values():
        possible = assignments.get(field, set())
        labels[field] = next(iter(possible)) if len(possible) == 1 else "UNKNOWN"
    return fields, labels, launches, scanned

def audit(path):
    from androguard.core.dex import DEX
    src = Path(path)
    need(src.is_file() and not src.is_symlink(), "P217_SIGNED_APK_FILE")
    need(hashlib.sha256(src.read_bytes()).hexdigest() == SIGNED_SHA,
         "P217_SIGNED_V138_SHA")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None, "P217_SIGNED_ZIP_CRC")
        dexnames = sorted(x for x in z.namelist()
                          if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", x))
        need(dexnames == ["classes.dex", "classes2.dex"],
             "P217_SIGNED_DEX_INVENTORY")
        dexes = [(n, DEX(z.read(n))) for n in dexnames]
    fields, labels, launches, scanned = inspect_dexes(dexes)
    print("P217_SIGNED_ORIGINAL_SHA_AND_ZIP=PASS")
    print("P217_ORIGINAL_CODE_METHODS_SCANNED=" + str(scanned))
    print("P217_MAIN_TYPED_LAUNCHER_FIELDS=" + str(len(fields)))
    print("P217_LOCAL_LINEAR_REGISTER_LINEAGE_ONLY=YES")
    print("P217_FIELD_CONTRACT_TYPES_CONFIRMED_LINEAR=" +
          str(sum(1 for x in labels.values() if x != "UNKNOWN")))
    for i, (pc, field) in enumerate(launches, 1):
        label = labels.get(field, "UNKNOWN") if field is not None else "UNKNOWN"
        print("P217_MAIN_LAUNCH_" + str(i) + "_BYTE_PC=" + str(pc))
        print("P217_MAIN_LAUNCH_" + str(i) + "_RECEIVER_FIELD=" +
              (str(field) if field is not None else "UNKNOWN"))
        print("P217_MAIN_LAUNCH_" + str(i) + "_CONTRACT_LINEAR_HINT=" + label)
    print("P217_NO_CFG_OR_INTERPROCEDURAL_PROOF=YES")
    print("P217_NO_PERMISSION_LITERAL_OR_RAW_OPERAND_LOGGING=YES")
    print("P217_PERMISSION_CONTROLLER_CAUSALITY=NOT_ATTESTED")
    print("P217_REAL_RUNTIME_REQUEST_OR_PERMISSION_DECISION=NOT_ATTESTED")
    print("P217_P209_PC3912_OR_P47_RUNTIME=NOT_ATTESTED")
    print("P217_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P217_SIGNED_ORIGINAL_LOCAL_LINEAGE_AUDIT=PASS")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    a = p.parse_args()
    try:
        audit(a.signed_original_v138)
    except Denied as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P217_FAIL_CLOSED_UNEXPECTED", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
