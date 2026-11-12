#!/usr/bin/env python3
"""P244 read-only feasibility: reuse P209 post-PC176 marker without relocation.

DEX 35c and 3rc use three 16-bit code units. Equality of width does not
prove validity of a replacement method, runtime process state or P47.
No APK, smali, signing, process or account mutation.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile
from collections import deque

class Refused(Exception):
    pass

def need(ok, code):
    if not ok:
        raise Refused("P244_DENY_" + code)

def may_write_receiver(op, output, receiver):
    no_writes = (
        op in ("nop", "check-cast", "throw", "monitor-enter",
               "monitor-exit", "packed-switch", "sparse-switch", "fill-array-data") or
        op.startswith(("invoke-", "if-", "goto", "return", "iput",
                       "sput", "aput", "filled-new-array"))
    )
    if no_writes:
        return False
    prefixes = ("move", "const", "new-", "iget", "sget", "aget",
                "instance-of", "array-length", "cmp", "neg", "not",
                "add", "sub", "mul", "div", "rem", "rsub", "and",
                "or", "xor", "shl", "shr", "ushr", "int-to",
                "long-to", "float-to", "double-to")
    if not op.startswith(prefixes):
        return True
    match = re.match(r"^\s*v([0-9]+)\s*(?:,|$)", output)
    if match is None:
        return True
    dest = int(match.group(1))
    return dest == receiver or (op.startswith("move-wide") and dest + 1 == receiver)

def receiver_unchanged(rows, edges, receiver, target=182):
    """Check all relevant normal-CFG paths, deny any write even benign writes."""
    need(0 in rows and target in rows and 0 <= receiver < 65536, "CFG_ANCHORS")
    need(len(rows) <= 12000, "CFG_SIZE")
    reverse = {pc: set() for pc in rows}
    for pc, nexts in edges.items():
        need(pc in rows, "UNKNOWN_CFG_SOURCE")
        for dest in nexts:
            need(dest in rows, "UNKNOWN_CFG_DESTINATION")
            reverse[dest].add(pc)
    relevant = {target}
    todo = [target]
    while todo:
        for pred in reverse[todo.pop()]:
            if pred not in relevant:
                relevant.add(pred)
                todo.append(pred)
    if 0 not in relevant:
        return "NOT_ATTESTED"
    seen = set()
    todo = deque([0])
    while todo:
        pc = todo.popleft()
        if pc in seen or pc not in relevant:
            continue
        seen.add(pc)
        if pc == target:
            continue
        op, operands = rows[pc]
        if may_write_receiver(op, operands, receiver):
            return "NOT_ATTESTED"
        todo.extend(x for x in edges.get(pc, ()) if x in relevant)
    return "ALL_MODELED_PREFIX_EDGES" if target in seen else "NOT_ATTESTED"

def same_width_candidate(old_op, old_bytes, receiver, outs_size, prefix_proof, handlers_to_182):
    """35c no-arg -> 3rc one-arg format possibility, NOT executable proof."""
    return (old_op == "invoke-static" and old_bytes == 6 and
            type(receiver) is int and 0 <= receiver <= 65535 and
            type(outs_size) is int and outs_size >= 1 and
            prefix_proof == "ALL_MODELED_PREFIX_EDGES" and
            handlers_to_182 == "NO")

def audit(original_path, derived_path):
    from androguard.core.dex import DEX
    from p238_signed_coroutine_capture import START, DESC, SIGNED_SHA
    from p243_signed_exception_handler_cfg import (
        exception_edges, handler_definitions, any_handler_reaches_target
    )
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "p204_oncreate_pc430"))
    import audit_original_oncreate_pc430 as cfg
    from verify_original_precall import compare as exact_p209_compare
    original, derived = Path(original_path), Path(derived_path)
    need(original.is_file() and not original.is_symlink(), "SIGNED_ORIGINAL_FILE")
    need(derived.is_file() and not derived.is_symlink(), "DISPOSABLE_DERIVED_FILE")
    need(hashlib.sha256(original.read_bytes()).hexdigest() == SIGNED_SHA, "SIGNED_SHA")
    def get_method(path, signed):
        with zipfile.ZipFile(path) as z:
            need(z.testzip() is None, "ZIP_CRC")
            names = sorted(n for n in z.namelist()
                           if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex", n))
            expected = (["classes.dex", "classes2.dex"] if signed
                        else ["classes.dex", "classes2.dex", "classes3.dex"])
            need(names == expected, "DEX_SET")
            dex = DEX(z.read("classes.dex"))
        found = [m for c in dex.get_classes() if c.get_name() == START
                 for m in c.get_methods() if m.get_name() == "invokeSuspend"
                 and "".join(m.get_descriptor().split()) == DESC]
        need(len(found) == 1 and found[0].get_code() is not None, "START2_UNIQUE")
        return found[0]
    o, d = get_method(original, True), get_method(derived, False)
    exact_p209_compare(o, d)
    code = o.get_code()
    need(code.get_ins_size() == 2 and 0 < code.get_registers_size() <= 512,
         "RECEIVER_REGISTER_SHAPE")
    receiver = code.get_registers_size() - code.get_ins_size()
    before = list(o.get_instructions_idx())
    pcs = dict(before)
    need(len(before) == len(pcs) and
         all(k in pcs for k in (0, 176, 182, 190, 194, 200, 202, 214, 3912)),
         "SIGNED_WINDOW_PCS")
    need(pcs[176].get_name() == "invoke-static/range" and
         "Lkotlin/ResultKt;->throwOnFailure" in pcs[176].get_output() and
         pcs[176].get_length() == 6 and
         pcs[182].get_name() == "iget-object" and
         pcs[190].get_name() == "iget-object" and
         pcs[194].get_name() == "invoke-static" and
         pcs[200].get_name() == "move-result-object" and
         pcs[202].get_name() == "if-eqz" and
         pcs[214].get_name() == "if-ne", "SIGNED_OPCODE_WINDOW")
    after = list(d.get_instructions_idx())
    mark = [(i, ins) for i, (_, ins) in enumerate(after)
            if ins.get_name() == "invoke-static" and
            "Lcom/dsh/android/p209/P209PreCallWitness;->markPostThrowOnFailure()V"
            in ins.get_output()]
    need(len(mark) == 1, "EXISTING_POSTRETURN_MARKER")
    index, marker = mark[0]
    need(0 < index < len(after) - 1 and
         after[index - 1][1].get_name() == "invoke-static/range" and
         "Lkotlin/ResultKt;->throwOnFailure" in after[index - 1][1].get_output() and
         after[index + 1][1].get_name() == "iget-object", "POSTRETURN_POSITION")
    nodes = [cfg.instruction(pc, ins.get_name(), ins.get_length(),
                            ins.get_ref_off() if cfg.is_cond(ins.get_name())
                            or cfg.is_jump(ins.get_name()) else None)
             for pc, ins in before]
    normal, unknown, _ = cfg.graph(nodes)
    need(not unknown, "UNMODELED_CFG")
    rows = {pc: (ins.get_name(), ins.get_output()) for pc, ins in before}
    tries = [(x.get_start_addr(), x.get_insn_count(), x.get_handler_off())
             for x in (code.get_tries() or [])]
    need(0 < len(tries) == code.get_tries_size(), "TRY_TABLE")
    exceptional, targets = exception_edges(
        rows, tries, handler_definitions(code), code.get_insns_size())
    handler_reach = any_handler_reaches_target(
        normal, exceptional, targets, target=182)
    prefix = receiver_unchanged(rows, normal, receiver)
    encoded = same_width_candidate(
        marker.get_name(), marker.get_length(), receiver,
        code.get_outs_size(), prefix, handler_reach)
    print("P244_ORIGINAL_SHA_AND_EXISTING_DERIVED_SLOT=PASS")
    print("P244_P209_ORIGINAL_BRANCH_TARGET_PARITY=PASS")
    print("P244_HANDLER_TO_PC182_REACHABLE=" + handler_reach)
    print("P244_PC176_POSTRETURN_P0_NOT_CLOBBERED=" + prefix)
    print("P244_35C_TO_3RC_SAME_WIDTH_ENCODING_CANDIDATE=" + ("YES" if encoded else "NO"))
    print("P244_ASSEMBLED_PROBE_PARITY=NOT_ATTESTED")
    print("P244_RUNTIME_PROCESS_STATE=NOT_ATTESTED")
    print("P244_CHILD_PID_UID_EPOCH=NOT_ATTESTED")
    print("P244_ORIGINAL_APK_DEX_OR_PRODUCTION_EDITED=NO")
    print("P244_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P244_READONLY_SLOT_FEASIBILITY_AUDIT=PASS")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("signed_original")
    parser.add_argument("disposable_derived")
    args = parser.parse_args()
    try:
        audit(args.signed_original, args.disposable_derived)
    except Refused as e:
        print(str(e))
        return 2
    except Exception:
        print("P244_READONLY_FEASIBILITY_DENY_UNEXPECTED")
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
