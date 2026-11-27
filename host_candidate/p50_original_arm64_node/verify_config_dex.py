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
from pathlib import Path
import sys
import zipfile
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'p245_build_only_probe'))
import strict_dex as strict

HOST_START = (b'Ljava/lang/ProcessBuilder;', b'start', (), b'Ljava/lang/Process;')


def verify(original, candidate, startup_diagnostics=False, owned_ready=False, owner_bound=False):
    strict.logger.remove()
    with Path(original).open('rb') as source:
        strict.need(hashlib.file_digest(source, 'sha256').hexdigest() ==
                    '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5',
                    'CONFIG_SIGNED_SOURCE_SHA')
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(candidate) as result:
        signed = strict.DexView(source.read('classes.dex'))
        current = strict.DexView(result.read('classes.dex'))
    owned_ready = owned_ready or owner_bound
    startup_diagnostics = startup_diagnostics or owned_ready
    if startup_diagnostics:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'engine_runtime'))
        import original_startup_diagnostics as diagnostics
        edits, extras = diagnostics.sanitizing_calls(owned_ready), diagnostics.METHODS
        if owned_ready:
            extras = extras | diagnostics.READY_METHODS
        if owner_bound:
            extras = extras | {diagnostics.OWNED_START, diagnostics.OWNED_PREPARE}
    else:
        edits, extras = {}, ()
    outside_bridges = {key: calls for key, calls in edits.items() if key != strict.START}
    counts = strict.verify_signed_baseline(signed, current, outside_bridges, extras)
    old, new = strict.index(signed.dex), strict.index(current.dex)
    for key in strict.SIGNED_BRIDGED:
        target = ('start' if key == strict.START else
                  'probeOrDeny' if key[1] == 'probeBoot' else 'configOrDeny')
        replacement = (b'Lcom/dsh/android/p40/P40ProcessBridge;', target.encode(),
                       (b'Ljava/lang/ProcessBuilder;',), b'Ljava/lang/Process;')
        sites = [(pc, signed.instruction(raw)[0]) for pc, raw in signed.rows(old[key]).items()
                 if raw[0] == 0x6e and signed.instruction(raw)[1] == HOST_START]
        strict.need(len(sites) == 1, 'CONFIG_EXACT_ONE_AUTHORIZED_START')
        pc, encoding = sites[0]
        calls = dict(edits.get(key, {}))
        strict.need(pc not in calls, 'CONFIG_TYPED_START_EDIT_COLLISION')
        if owner_bound and key == strict.START:
            strict.need(pc == diagnostics.OWNED_START_PC and encoding == bytes.fromhex('6e100000'),
                        'OWNER_BOUND_SIGNED_CALLSITE_DRIFT')
            calls[pc] = ((encoding, HOST_START), diagnostics.OWNED_START_INVOKE)
        else:
            calls[pc] = ((encoding, HOST_START), (b'\x71' + encoding[1:], replacement))
        if owner_bound and key == strict.START:
            diagnostics.verify_owned_entry(strict, signed, current, old[key], new[key], calls)
        else:
            strict.compare_signed_code(old[key], new[key], signed, current, calls)
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
    if startup_diagnostics:
        diagnostics.verify_helper(strict, current, new, owned_ready, owner_bound)
        print('ORIGINAL_STARTUP_DIAGNOSTICS_NINE_CALLS_AND_HELPER=PASS_STATIC')
        if owned_ready:
            print('ORIGINAL_MAIN_OWNED_READY_REGEX_AND_TWO_PUBLICATIONS=PASS_STATIC')
        if owner_bound:
            print('ORIGINAL_MAIN_OWNER_BOUND_PC3912_AND_EXACT_HANDOFF_WRAPPER=PASS_STATIC')
            print('ORIGINAL_MAIN_EXACT_ISOLATED_PRELAUNCH_AND_ORIGINAL_POST_SPAWN=PASS_STATIC')
        print('ORIGINAL_CONFIG_SIGNED_UNRELATED_METHODS=PASS count=' + str(counts['METHODS'] - len(outside_bridges)))
        print('ORIGINAL_CONFIG_THREE_TYPED_STARTS_AND_EXPLICIT_DIAGNOSTIC_SITES=PASS')
    else:
        print('ORIGINAL_CONFIG_SIGNED_UNRELATED_METHODS=PASS count=' + str(counts['METHODS']))
        print('ORIGINAL_CONFIG_THREE_TARGET_METHODS_ONLY_TYPED_START_CHANGED=PASS')
    print('ORIGINAL_CONFIG_ART_AND_ENGINE_READY=NOT_ATTESTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('--negative-checks', action='store_true')
    parser.add_argument('--startup-diagnostics', action='store_true')
    parser.add_argument('--owned-ready', action='store_true')
    parser.add_argument('--owner-bound', action='store_true')
    args = parser.parse_args()
    args.owned_ready = args.owned_ready or args.owner_bound
    verify(args.original, args.candidate, args.startup_diagnostics, args.owned_ready, args.owner_bound)
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
        if args.startup_diagnostics or args.owned_ready:
            import original_startup_diagnostics as diagnostics
            helper = methods[diagnostics.REDACT]
            reader = methods[diagnostics.READER]
            replacement = diagnostics.sanitizing_calls()[diagnostics.READER][228][1][1]
            changed = [pc for pc, raw in view.rows(reader).items() if raw[0] == 0x71 and
                       view.instruction(raw)[1] == replacement]
            strict.need(len(changed) == 1, 'STARTUP_DIAGNOSTICS_NEGATIVE_ANCHOR')
            raw_argument = reader.get_code().get_off() + 16 + changed[0] + 4
            mutations['STARTUP_HISTORY_REGISTER'] = (raw_argument, bytes([payload[raw_argument] ^ 0x10]))
            mutations['STARTUP_HELPER_BRANCH'] = (helper.get_code().get_off() + 16, b'\x39')
            if args.owned_ready:
                replacement = diagnostics.sanitizing_calls(True)[diagnostics.READER][294][1][1]
                announce = [pc for pc, raw in view.rows(reader).items() if raw[0] == 0x71 and
                            view.instruction(raw)[1] == replacement]
                strict.need(len(announce) == 1, 'OWNED_READY_MUTATION_ANCHOR')
                argument = reader.get_code().get_off() + 16 + announce[0] + 1
                mutations['OWNED_READY_PROCESS_REGISTER'] = (argument, bytes([payload[argument] ^ 0x01]))
                key = (diagnostics.OWNER, 'findReady', diagnostics.FIND_READY)
                gate_rows = view.rows(methods[key])
                branch = next(pc for pc, raw in gate_rows.items() if raw[0] == 0x38)
                mutations['OWNED_READY_HELPER_BRANCH'] = (methods[key].get_code().get_off() + 16 + branch, b'\x39')
            if args.owner_bound:
                offset = methods[strict.START].get_code().get_off() + 16 + diagnostics.OWNED_START_PC + 4
                mutations['ORIGINAL_OWNER_REGISTER'] = (offset, bytes([payload[offset] ^ 0x10]))
                entry = methods[strict.START].get_code().get_off() + 16 + diagnostics.OWNED_ENTRY_PC
                mutations['ORIGINAL_OWNER_ENTRY_BRANCH'] = (entry + 2, struct.pack('<h', 2))
                footer = entry + 2 * struct.unpack_from('<h', payload, entry + 2)[0]
                argument = footer + 8  # method register word of prepareOwned in the verified footer
                mutations['ORIGINAL_OWNER_FOOTER_ARGUMENT'] = (argument, bytes([payload[argument] ^ 1]))
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
                    verify(args.original, negative, args.startup_diagnostics, args.owned_ready, args.owner_bound)
                except strict.Deny as denied:
                    expected = {'STARTUP_HISTORY_REGISTER': 'P246_DENY_SIGNED_APPROVED_INVOKE',
                                'STARTUP_HELPER_BRANCH': 'P246_DENY_STARTUP_DIAGNOSTICS_HELPER_BODY',
                                'OWNED_READY_PROCESS_REGISTER': 'P246_DENY_SIGNED_APPROVED_INVOKE',
                                'ORIGINAL_OWNER_REGISTER': 'P246_DENY_OWNED_ENTRY_ORIGINAL_INSTRUCTION',
                                'ORIGINAL_OWNER_ENTRY_BRANCH': 'P246_DENY_OWNED_ENTRY_BRANCH',
                                'ORIGINAL_OWNER_FOOTER_ARGUMENT': 'P246_DENY_OWNED_ENTRY_FOOTER_BODY',
                                'OWNED_READY_HELPER_BRANCH': 'P246_DENY_STARTUP_DIAGNOSTICS_HELPER_BODY'}
                    if label in expected and str(denied) != expected[label]:
                        raise RuntimeError('STARTUP_MUTATION_WRONG_DENIAL_' + label) from denied
                    print('ORIGINAL_CONFIG_DEX_MUTATION_' + label + '=DENY reason=' + str(denied))
                else:
                    raise RuntimeError('CONFIG_MUTATION_ACCEPTED_' + label)
                gc.collect()
