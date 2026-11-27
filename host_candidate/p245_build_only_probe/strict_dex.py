#!/usr/bin/env python3
"""Static DEX gate for the existing P245 diagnostic. Never authorizes execution."""

import argparse
from collections import Counter
from functools import lru_cache
from pathlib import Path
import re
import struct
import sys
import zipfile

from androguard.core.dex import DEX
from loguru import logger

import p245_build_only_probe as original

sys.path[:0] = [
    "host_candidate/p246_exception_semantics",
    "host_candidate/p249_dual_diff",
    "host_candidate/p285_shadow_verifier",
    "host_candidate/p298_other_pool_refs",
]
from p246_exception_semantics import Deny, decode, index, need
from p249_dual_diff import HELPER, START, seal
from p285_shadow_verifier import capture_from_baseline, try_catch
from p298_other_pool_refs import INVOKE_METHOD, REF_SPEC, UNSUPPORTED

DEX_HEADER_TABLES = {"STRING": 56, "TYPE": 64, "PROTO": 72, "FIELD": 80, "METHOD": 88}
BRANCHES = {0x28: "<b", 0x29: "<h", 0x2A: "<i", **dict.fromkeys(range(0x32, 0x3E), "<h")}
PAYLOAD_BRANCHES = {0x26: 0x0300, 0x2B: 0x0100, 0x2C: 0x0200}
PAYLOAD_TAGS = set(PAYLOAD_BRANCHES.values())
OLD_METHOD = (b"Lcom/dsh/android/p209/P209PreCallWitness;", b"markPostThrowOnFailure", (), b"V")
NEW_METHOD = (original.OWNER.encode(), original.NAME.encode(), (original.OWNER.encode(),), b"V")
SIGNED_GETTER = (
    b"Lcom/dsh/android/EngineManager;", b"access$getProcess$p",
    (b"Lcom/dsh/android/EngineManager;",), b"Ljava/lang/Process;",
)
LOG_METHOD = (b"Landroid/util/Log;", b"i", (b"Ljava/lang/String;",) * 2, b"I")
SAFE_TAGS = {b"DSH", b"MainActivity", b"Android", b"Log"}
CODE_METHODS = 52_014
SIGNED_CODE_METHODS = 52_011
SIGNED_BRIDGED = {
    START,
    ("Lcom/dsh/android/EngineManager;", "probeBoot", "(Ljava/lang/String;Ljava/util/List;J)Lcom/dsh/android/EngineManager$ProbeResult;"),
    ("Lcom/dsh/android/EngineManager;", "runDumpConfig", "()Lcom/dsh/android/EngineManager$DumpResult;"),
}
P40_METHODS = {
    ("Lcom/dsh/android/p40/P40ProcessBridge;", name, "(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;")
    for name in ("start", "probeOrDeny", "configOrDeny")
}
SIGNATURE_ENTRY = re.compile(r"META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))", re.IGNORECASE)


class DexView:
    def __init__(self, data):
        need(data[:8] in (b"dex\n035\0", b"dex\n037\0", b"dex\n038\0", b"dex\n039\0"), "DEX_FORMAT")
        need(struct.unpack_from("<III", data, 32) == (len(data), 112, 0x12345678), "DEX_HEADER")
        self.data = data
        self.dex = DEX(data)
        self.tables = {kind: struct.unpack_from("<II", data, offset) for kind, offset in DEX_HEADER_TABLES.items()}
        self.strings = {item.get_off(): item for item in self.dex.get_string_data_item()}
        self.resolve = lru_cache(maxsize=None)(self._resolve)

    def _resolve(self, kind, idx):
        count, start = self.tables[kind]
        need(0 <= idx < count, "POOL_INDEX")
        if kind == "STRING":
            offset, = struct.unpack_from("<I", self.data, start + 4 * idx)
            need(offset in self.strings, "STRING_DATA_OFFSET")
            item = self.strings[offset]
            value = item.get_data()[:-1]
            # Every MUTF-8 leading byte represents one UTF-16 code unit.
            # Keep the encoded bytes, including surrogate pairs and NUL.
            need(sum(byte & 0xC0 != 0x80 for byte in value) == item.get_utf16_size(), "STRING_UTF16_SIZE")
            return value
        if kind == "TYPE":
            idx, = struct.unpack_from("<I", self.data, start + 4 * idx)
            return self.resolve("STRING", idx)
        if kind == "PROTO":
            _, returned, offset = struct.unpack_from("<III", self.data, start + 12 * idx)
            params = ()
            if offset:
                count, = struct.unpack_from("<I", self.data, offset)
                need(offset % 4 == 0 and count <= (len(self.data) - offset - 4) // 2, "PROTO_PARAMETERS")
                params = tuple(self.resolve("TYPE", val) for val, in struct.iter_unpack("<H", self.data[offset + 4:offset + 4 + 2 * count]))
            return params, self.resolve("TYPE", returned)
        owner, ref, name = struct.unpack_from("<HHI", self.data, start + 8 * idx)
        identity = (self.resolve("TYPE", owner), self.resolve("STRING", name))
        if kind == "FIELD":
            return (*identity, self.resolve("TYPE", ref))
        return (*identity, *self.resolve("PROTO", ref))

    def rows(self, method):
        code = method.get_code()
        start = code.get_off() + 16
        end = start + 2 * code.get_insns_size()
        need(start <= end <= len(self.data), "CODE_RANGE")
        cursor = 0
        rows = {}
        for pc, inst in method.get_instructions_idx():
            width = inst.get_length()
            need(pc == cursor and width >= 2 and width % 2 == 0 and start + pc + width <= end, "CODE_LAYOUT")
            raw = self.data[start + pc:start + pc + width]
            rows[pc] = raw
            cursor += width
        need(start + cursor == end, "CODE_COVERAGE")
        return rows

    def instruction(self, raw):
        op = raw[0]
        need(op not in UNSUPPORTED, "UNSUPPORTED_OPCODE")
        if op in INVOKE_METHOD:
            spec = ("METHOD", 6, 2)
        else:
            spec = REF_SPEC.get(op)
        if spec is None:
            return raw, None
        kind, length, width = spec
        need(len(raw) == length, "REFERENCE_WIDTH")
        value = self.resolve(kind, int.from_bytes(raw[2:2 + width], "little"))
        return raw[:2] + raw[2 + width:], value


def validate_targets(rows):
    """Check byte-offset branches and switch entries relative to their users."""
    for pc, raw in rows.items():
        op = raw[0]
        if op in BRANCHES:
            offset = 1 if op == 0x28 else 2
            target = pc + 2 * struct.unpack_from(BRANCHES[op], raw, offset)[0]
            need(target in rows and rows[target][:2] not in (b"\0\1", b"\0\2", b"\0\3"), "BRANCH_TARGET")
        elif op in PAYLOAD_BRANCHES:
            target = pc + 2 * struct.unpack_from("<i", raw, 2)[0]
            need(target % 4 == 0 and target in rows, "PAYLOAD_TARGET")
            payload = rows[target]
            tag, size = struct.unpack_from("<HH", payload)
            need(tag == PAYLOAD_BRANCHES[op], "PAYLOAD_TYPE")
            if tag != 0x0300:
                offsets = payload[8:] if tag == 0x0100 else payload[4 + 4 * size:]
                need(len(offsets) == 4 * size, "SWITCH_PAYLOAD_SIZE")
                for offset, in struct.iter_unpack("<i", offsets):
                    dest = rows.get(pc + 2 * offset)
                    need(dest is not None and int.from_bytes(dest[:2], "little") not in PAYLOAD_TAGS, "SWITCH_TARGET")


def compare_code(left, right, base, candidate, is_target):
    lc, rc = left.get_code(), right.get_code()
    frame = (lc.get_registers_size(), lc.get_ins_size(), lc.get_outs_size())
    need(frame == (rc.get_registers_size(), rc.get_ins_size(), rc.get_outs_size()), "REGISTER_FRAME")
    need(decode(left, base.dex) == decode(right, candidate.dex), "EXCEPTION_OR_CODE_SIZE")
    lrows, rrows = base.rows(left), candidate.rows(right)
    need(lrows.keys() == rrows.keys(), "INSTRUCTION_OFFSETS")
    validate_targets(lrows)
    validate_targets(rrows)
    edits = 0
    for pc, raw in lrows.items():
        before, after = base.instruction(raw), candidate.instruction(rrows[pc])
        if before == after:
            continue
        need(is_target and before == (b"\x71\x00\x00\x00", OLD_METHOD), "UNAPPROVED_INSTRUCTION_CHANGE")
        need(frame[1] == 2 and frame[2] >= 1 and frame[0] > 1, "START_RECEIVER_FRAME")
        receiver = (frame[0] - frame[1]).to_bytes(2, "little")
        need(after == (b"\x77\x01" + receiver, NEW_METHOD), "START_HELPER_CALL")
        edits += 1
    need(edits == int(is_target), "START_EDIT_COUNT")


def ordinal_tries(tries, ordinals):
    """Represent dispatch per protected range and coalesce equal neighbors."""
    spans = []
    for start, length, (typed, catchall) in tries:
        begin, end = ordinals[2 * start], ordinals[2 * (start + length)]
        handlers = (tuple((kind, ordinals[2 * target]) for kind, target in typed),
                    None if catchall is None else ordinals[2 * catchall])
        if spans and spans[-1][1:] == (begin, handlers):
            begin = spans.pop()[0]
        spans.append((begin, end, handlers))
    return tuple(spans)


def relocated_instruction(view, rows, ordinals, pc, raw):
    """Compare the same instruction and destination by ordinal, never by name."""
    op = raw[0]
    fixed, ref = view.instruction(raw)
    if op in (0x1A, 0x1B):
        index = int.from_bytes(raw[2:], "little")
        need(op == 0x1A or index > 0xFFFF, "UNNECESSARY_JUMBO")
        return (b"\x1a" + raw[1:2], ref)
    if op in BRANCHES:
        offset = 1 if op == 0x28 else 2
        delta, = struct.unpack_from(BRANCHES[op], raw, offset)
        return (raw[:offset], ordinals[pc + 2 * delta])
    if op in PAYLOAD_BRANCHES:
        delta, = struct.unpack_from("<i", raw, 2)
        target = pc + 2 * delta
        payload = rows[target]
        if op == 0x26:
            return (raw[:2], ordinals[target], payload)
        _, size = struct.unpack_from("<HH", payload)
        pivot = 8 if op == 0x2B else 4 + 4 * size
        destinations = tuple(ordinals[pc + 2 * off] for off, in struct.iter_unpack("<i", payload[pivot:]))
        return (raw[:2], ordinals[target], payload[:pivot], destinations)
    # Switch payload targets are relative to each referring instruction.
    # The case keys and each destination were compared with their user.
    if int.from_bytes(raw[:2], "little") in (0x0100, 0x0200):
        return (raw[:2], len(raw))
    return (fixed, ref)


def compare_signed_code(left, right, signed, base, invoke_edits=None):
    """Account for assembler layout changes in methods outside the three seams."""
    lc, rc = left.get_code(), right.get_code()
    need((lc.get_registers_size(), lc.get_ins_size()) == (rc.get_registers_size(), rc.get_ins_size()), "SIGNED_REGISTER_FRAME")
    lsize, ltry = decode(left, signed.dex)
    rsize, rtry = decode(right, base.dex)
    lrows, rrows = signed.rows(left), base.rows(right)
    need(len(lrows) == len(rrows), "SIGNED_INSTRUCTION_COUNT")
    validate_targets(lrows)
    validate_targets(rrows)
    lo = {pc: n for n, pc in enumerate((*lrows, 2 * lsize))}
    ro = {pc: n for n, pc in enumerate((*rrows, 2 * rsize))}
    need(ordinal_tries(ltry, lo) == ordinal_tries(rtry, ro), "SIGNED_EXCEPTION_DISPATCH")
    same_offsets = lrows.keys() == rrows.keys()
    edits = dict(invoke_edits or {})
    for (old_pc, old_raw), (new_pc, new_raw) in zip(lrows.items(), rrows.items()):
        if old_pc in edits:
            before, after = edits.pop(old_pc)
            need(old_raw[0] in (0x6e, 0x71, 0x72) and new_raw[0] == 0x71 and
                 len(old_raw) == len(new_raw) == 6 and signed.instruction(old_raw) == before and
                 base.instruction(new_raw) == after, "SIGNED_APPROVED_INVOKE")
            continue
        if old_raw[0] != new_raw[0]:
            need((old_raw[0], new_raw[0]) == (0x1A, 0x1B), "SIGNED_ENCODING_CHANGE")
        if same_offsets and old_raw[0] == new_raw[0]:
            before, after = signed.instruction(old_raw), base.instruction(new_raw)
        else:
            before = relocated_instruction(signed, lrows, lo, old_pc, old_raw)
            after = relocated_instruction(base, rrows, ro, new_pc, new_raw)
        need(before == after, "SIGNED_INSTRUCTION_SEMANTICS")
    need(not edits, "SIGNED_APPROVED_INVOKE_MISSING")

    # A lower outs_size is valid only when it still covers every encoded
    # method invocation. Filled-new-array creates its own array instead of
    # transferring words to a callee and doesn't use the outgoing frame.
    if lc.get_outs_size() != rc.get_outs_size():
        required = max((raw[1] >> 4 if raw[0] <= 0x72 else raw[1]
                        for raw in rrows.values() if raw[0] in INVOKE_METHOD), default=0)
        need(required <= rc.get_outs_size() < lc.get_outs_size(), "SIGNED_OUTGOING_CAPACITY")
    return (lc.get_outs_size() != rc.get_outs_size(), not same_offsets, ltry != rtry)


def verify_signed_baseline(signed, base, invoke_edits=None, added_methods=()):
    """Census of signed v138 methods outside the separately audited bridges."""
    source, baseline = index(signed.dex), index(base.dex)
    edits = invoke_edits or {}
    additions = set(added_methods)
    need(SIGNED_BRIDGED <= source.keys() and edits.keys() <= (source.keys() - SIGNED_BRIDGED) and
         not additions.intersection(source.keys() | P40_METHODS) and
         set(baseline) == set(source) | P40_METHODS | additions, "SIGNED_METHOD_SET")
    counts = Counter()
    for key, left in source.items():
        right = baseline[key]
        need(left.get_access_flags() == right.get_access_flags(), "SIGNED_METHOD_FLAGS")
        need((left.get_code() is None) == (right.get_code() is None), "SIGNED_METHOD_CODE_PRESENCE")
        if left.get_code() is None or key in SIGNED_BRIDGED:
            continue
        counts["METHODS"] += 1
        for name, changed in zip(("OUTGOING_CAPACITY", "WIDTH_RELOCATED", "TRY_LAYOUT"),
                                 compare_signed_code(left, right, signed, base, edits.get(key))):
            counts[name] += changed
    need(counts["METHODS"] == SIGNED_CODE_METHODS - len(SIGNED_BRIDGED), "SIGNED_CODE_METHOD_CENSUS")
    return counts


def verify_helper(method, base, candidate):
    code = method.get_code()
    need(method.get_access_flags() == 0x9 and code is not None, "HELPER_STATIC_PUBLIC")
    need((code.get_registers_size(), code.get_ins_size(), code.get_outs_size()) == (5, 1, 2), "HELPER_FRAME")
    raw_rows = candidate.rows(method)
    validate_targets(raw_rows)
    rows = [(pc // 2, ins.get_name(), ins.get_length(), ins, None) for pc, ins in method.get_instructions_idx()]
    need(len(rows) == 14, "HELPER_LENGTH")
    enc, refs = zip(*(candidate.instruction(raw) for raw in raw_rows.values()))
    need(enc[0] == b"\x54\x40" and enc[2] == b"\x71\x10\x00\x00" and
         enc[3] == b"\x0c\x00" and enc[10] == b"\x71\x20\x21\x00" and
         enc[11:] == (b"\x0e\x00", b"\x0d\x00", b"\x0e\x00"), "HELPER_OPERANDS")
    for i, target in ((1, 8), (4, 8), (7, 10)):
        delta = rows[target][0] - rows[i][0]
        expected = b"\x28" + struct.pack("<b", delta) if i == 7 else b"\x38\x00" + struct.pack("<h", delta)
        need(enc[i] == expected, "HELPER_BRANCH")
    capture = capture_from_baseline(base.dex)
    need(capture is not None and refs[0] == (NEW_METHOD[0], capture.encode(), SIGNED_GETTER[0]), "HELPER_CAPTURE")
    need(refs[2] == SIGNED_GETTER, "HELPER_GETTER")
    need(refs[10] == LOG_METHOD, "HELPER_LOG")
    for i, register in ((5, 1), (6, 2), (8, 1), (9, 2)):
        need(enc[i] in (bytes((0x1A, register)), bytes((0x1B, register))), "HELPER_LITERAL_REGISTER")
    need(refs[5] == refs[8] and refs[5] in SAFE_TAGS and refs[6] == b"true" and refs[9] == b"false", "HELPER_LITERALS")
    need(try_catch(method, candidate.dex, rows) == "PASS", "HELPER_EXCEPTION_TABLE")


def verify_methods(signed, base, candidate):
    baseline, derived = index(base.dex), index(candidate.dex)
    need(START in baseline and HELPER not in baseline and set(derived) == set(baseline) | {HELPER}, "METHOD_SET")
    source = index(signed.dex)[START]
    getter = signed.rows(source)[194]
    need(getter[0] == 0x71 and signed.instruction(getter)[1] == SIGNED_GETTER, "SIGNED_START_GETTER")
    examined = 0
    for key, left in baseline.items():
        right = derived[key]
        need(left.get_access_flags() == right.get_access_flags(), "METHOD_FLAGS")
        need((left.get_code() is None) == (right.get_code() is None), "METHOD_CODE_PRESENCE")
        if left.get_code() is not None:
            compare_code(left, right, base, candidate, key == START)
            examined += 1
    need(examined == CODE_METHODS, "CODE_METHOD_CENSUS")
    verify_helper(derived[HELPER], base, candidate)
    return examined


def verify(signed_path, base_path, candidate_path):
    seal(signed_path)
    with zipfile.ZipFile(signed_path) as source, zipfile.ZipFile(base_path) as base, zipfile.ZipFile(candidate_path) as derived:
        for apk in (base, derived):
            need(len(set(apk.namelist())) == len(apk.namelist()) and apk.testzip() is None, "APK_ZIP")
        def protected(apk):
            return {name for name in apk.namelist() if not name.endswith("/") and not SIGNATURE_ENTRY.fullmatch(name)}

        names = protected(base)
        need(names == protected(derived) and {"classes.dex", "classes2.dex", "classes3.dex", "AndroidManifest.xml"} <= names, "APK_MEMBERS")
        for name in sorted(names - {"classes.dex"}):
            need(base.read(name) == derived.read(name), "UNAPPROVED_APK_MEMBER_CHANGE")
        need(source.read("classes2.dex") == base.read("classes2.dex"), "ORIGINAL_SECONDARY_DEX")
        signed_dex, base_dex, derived_dex = (DexView(apk.read("classes.dex")) for apk in (source, base, derived))
        comparable = verify_signed_baseline(signed_dex, base_dex)
        return verify_methods(signed_dex, base_dex, derived_dex), comparable


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("signed-original", "base", "candidate"):
        ap.add_argument("--" + name, type=Path, required=True)
    args = ap.parse_args()
    logger.remove()
    try:
        examined, signed_comparison = verify(args.signed_original, args.base, args.candidate)
    except Deny as exc:
        print("P245_STRICT_" + str(exc), file=sys.stderr)
        return 2
    except Exception:
        print("P245_STRICT_DENY_UNREADABLE_INPUT", file=sys.stderr)
        return 2
    print(f"P245_STRICT_BASELINE_CODE_METHODS={examined}")
    for name, count in signed_comparison.items():
        print(f"P245_STRICT_SIGNED_UNRELATED_{name}={count}")
    print("P245_STRICT_DIAGNOSTIC_DERIVED_BASELINE=PASS")
    print("P245_ART_AND_RELEASE=NOT_ATTESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
