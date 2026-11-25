#!/usr/bin/env python3
"""Strict original-method comparison for the three explicitly authorized bridges.
Only the one ProcessBuilder.start invocation per method may become its typed P40
call. All other instructions, operands, frames, branches and try dispatch retain
strict_dex's signed-original checks. This grants no runtime/release approval.
"""
import argparse
import gc
import hashlib
import struct
import tempfile
from copy import copy
from pathlib import Path
import sys
import zipfile
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p245_build_only_probe'))
import strict_dex as strict

HOST_START = (b'Ljava/lang/ProcessBuilder;', b'start', (), b'Ljava/lang/Process;')


def verify(original, candidate):
    strict.logger.remove()
    with Path(original).open('rb') as source:
        strict.need(hashlib.file_digest(source, 'sha256').hexdigest() ==
                    '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5',
                    'CONFIG_SIGNED_SOURCE_SHA')
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(candidate) as result:
        signed = strict.DexView(source.read('classes.dex'))
        current = strict.DexView(result.read('classes.dex'))
    counts = strict.verify_signed_baseline(signed, current)
    old, new = strict.index(signed.dex), strict.index(current.dex)
    for key in strict.SIGNED_BRIDGED:
        target = ('start' if key == strict.START else
                  'probeOrDeny' if key[1] == 'probeBoot' else 'configOrDeny')
        replacement = (b'Lcom/dsh/android/p40/P40ProcessBridge;', target.encode(),
                       (b'Ljava/lang/ProcessBuilder;',), b'Ljava/lang/Process;')
        adjusted = copy(signed)
        adjusted.resolve = lambda kind, idx: (replacement if kind == 'METHOD' and
            signed.resolve(kind, idx) == HOST_START else signed.resolve(kind, idx))
        def rows(method):
            result = signed.rows(method)
            sites = [pc for pc, raw in result.items() if raw[0] == 0x6e and
                     signed.instruction(raw)[1] == HOST_START]
            strict.need(len(sites) == 1, 'CONFIG_EXACT_ONE_AUTHORIZED_START')
            pc = sites[0]
            result[pc] = bytes([0x71]) + result[pc][1:]
            return result
        adjusted.rows = rows
        strict.compare_signed_code(old[key], new[key], adjusted, current)
        bridge = new[('Lcom/dsh/android/p40/P40ProcessBridge;', target,
                      '(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;')]
        raw = list(current.rows(bridge).values())
        expected = (b'Lcom/dsh/android/p47/P47LaunchGate;',
                    ('startOrDeny' if target == 'start' else target).encode(),
                    (b'Ljava/lang/ProcessBuilder;',), b'Ljava/lang/Process;')
        code = bridge.get_code()
        strict.need(bridge.get_access_flags() == 0x9 and len(raw) == 3 and
                    (code.get_registers_size(), code.get_ins_size(), code.get_outs_size()) == (2, 1, 1) and
                    current.instruction(raw[0]) == (b'\x71\x10\x01\x00', expected) and
                    raw[1:] == [b'\x0c\x00', b'\x11\x00'] and
                    not strict.decode(bridge, current.dex)[1], 'CONFIG_EXACT_TYPED_BRIDGE')
    print('ORIGINAL_CONFIG_SIGNED_UNRELATED_METHODS=PASS count=' + str(counts['METHODS']))
    print('ORIGINAL_CONFIG_THREE_TARGET_METHODS_ONLY_TYPED_START_CHANGED=PASS')
    print('ORIGINAL_CONFIG_ART_AND_ENGINE_READY=NOT_ATTESTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--negative-checks', action='store_true')
    args = parser.parse_args()
    verify(args.original, args.candidate)
    if args.negative_checks:
        with zipfile.ZipFile(args.candidate) as archive:
            payload = archive.read('classes.dex')
        view = strict.DexView(payload)
        methods = strict.index(view.dex)
        dump = next(methods[key] for key in strict.SIGNED_BRIDGED if key[1] == 'runDumpConfig')
        rows = view.rows(dump)
        call = next(pc for pc, raw in rows.items() if raw[0] == 0x71 and
                    view.instruction(raw)[1] == (b'Lcom/dsh/android/p40/P40ProcessBridge;',
                    b'configOrDeny', (b'Ljava/lang/ProcessBuilder;',), b'Ljava/lang/Process;'))
        start = dump.get_code().get_off() + 16
        bridge_key = ('Lcom/dsh/android/p40/P40ProcessBridge;', 'configOrDeny',
                      '(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;')
        bridge_start = methods[bridge_key].get_code().get_off() + 16
        wrong_ref = next(idx for idx in range(view.tables['METHOD'][0]) if
                         view.resolve('METHOD', idx) ==
                         (b'Lcom/dsh/android/p47/P47LaunchGate;', b'probeOrDeny',
                          (b'Ljava/lang/ProcessBuilder;',), b'Ljava/lang/Process;'))
        strict.need(dump.get_code().get_tries_size() > 0, 'CONFIG_NEGATIVE_TRY_REQUIRED')
        try_offset = (start + 2 * dump.get_code().get_insns_size() + 3) & ~3
        try_start, length = struct.unpack_from('<IH', payload, try_offset)
        previous = max(pc // 2 for pc in rows if try_start < pc // 2 < try_start + length)
        shortened = previous - try_start
        literal = next((method.get_code().get_off() + 16 + pc + 1)
                       for key, method in methods.items() if key not in strict.SIGNED_BRIDGED and
                       method.get_code() for pc, raw in view.rows(method).items() if raw[0] == 0x12)
        mutations = {
            'TARGET_REGISTER': (start + call + 4, bytes([payload[start + call + 4] ^ 1])),
            'TYPED_MODE': (bridge_start + 2, struct.pack('<H', wrong_ref)),
            'TRY_RANGE': (try_offset + 4, struct.pack('<H', shortened)),
            'UNRELATED_LITERAL': (literal, bytes([payload[literal] ^ 0x10])),
        }
        del rows, methods, view, dump
        gc.collect()
        with tempfile.TemporaryDirectory(prefix='original-config-negative-') as directory:
            negative = Path(directory) / 'mutated-NOT-INSTALLABLE.apk'
            for label, (offset, replacement) in mutations.items():
                changed = bytearray(payload)
                changed[offset:offset + len(replacement)] = replacement
                # Keep the DEX envelope valid so rejection proves the semantic
                # check, rather than only a stale header checksum.
                changed[12:32] = hashlib.sha1(changed[32:]).digest()
                struct.pack_into('<I', changed, 8, zlib.adler32(changed[12:]))
                with zipfile.ZipFile(negative, 'w') as archive:
                    archive.writestr('classes.dex', changed)
                try:
                    verify(args.original, negative)
                except strict.Deny as denied:
                    print('ORIGINAL_CONFIG_DEX_MUTATION_' + label + '=DENY reason=' + str(denied))
                else:
                    raise RuntimeError('CONFIG_MUTATION_ACCEPTED_' + label)
                gc.collect()
