#!/usr/bin/env python3
"""Redact v138 startup diagnostics at the signed, inventoried callsites."""

import argparse
import hashlib
import re
from collections import Counter
from pathlib import Path

PACKAGE = 'Lcom/dsh/android/'
OWNER = PACKAGE + 'engine/OriginalStartupDiagnostics;'
STRING = 'Ljava/lang/String;'
BUILDER = 'Ljava/lang/StringBuilder;'
LOG = PACKAGE + 'log/LogStore;'
DEQUE = 'Lkotlin/collections/ArrayDeque;'
LIST = 'Ljava/util/List;'
OBJECT = 'Ljava/lang/Object;'
HIDDEN = '[launch credential withheld]'
ORIGINAL_SHA = '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
ENGINE = PACKAGE + 'EngineManager;'
STARTUP = PACKAGE + 'engine/OriginalMainStartup;'
PROCESS = 'Ljava/lang/Process;'
PROCESS_BUILDER = 'Ljava/lang/ProcessBuilder;'
MAIN_HANDOFF = PACKAGE + 'engine/OriginalMainOwnerHandoff;'
FLOW = 'Lkotlinx/coroutines/flow/MutableStateFlow;'
REGEX = 'Lkotlin/text/Regex;'
CHARSEQ = 'Ljava/lang/CharSequence;'
MATCH = 'Lkotlin/text/MatchResult;'
FIND = f'({REGEX}{CHARSEQ}II{OBJECT}){MATCH}'
FIND_READY = f'({REGEX}{CHARSEQ}II{PROCESS}){MATCH}'

# Receiver, original name and argument, return descriptor, invoke mnemonic.
WRAPPERS = {
    'append': (BUILDER, 'append', STRING, BUILDER, 'invoke-virtual'),
    'store': (LOG, 'engine', STRING, 'V', 'invoke-virtual'),
    'history': (DEQUE, 'addLast', OBJECT, 'V', 'invoke-virtual'),
    'probeTail': (LIST, 'add', OBJECT, 'Z', 'invoke-interface'),
}

START = (PACKAGE + 'EngineManager$start$2;', 'invokeSuspend', f'({OBJECT}){OBJECT}')
READER = (START[0], 'invokeSuspend$lambda$9',
          '(Ljava/lang/Process;Ljava/util/concurrent/CountDownLatch;Lkotlinx/coroutines/CoroutineScope;'
          'Lcom/dsh/android/EngineManager;Lkotlin/jvm/internal/Ref$ObjectRef;Lkotlin/text/Regex;)V')

# Byte PCs from signed classes.dex. The mask records each original invoke's
# opcode and full argument register encoding, independent of pool position.
SITES = {
    READER: [(156, '6e202500', 'store', 'v5, v2'),
             (188, '6e202600', 'append', 'v6, v2'),
             (228, '6e202600', 'history', 'v6, v2')],
    START: [(4700, '6e203200', 'append', 'v2, v3'),
            (4776, '6e203200', 'append', 'v2, v3')],
    (PACKAGE + 'EngineManager;', 'probeBoot$lambda$146$lambda$145',
     '(Ljava/util/List;Ljava/util/concurrent/atomic/AtomicBoolean;Ljava/lang/String;)Lkotlin/Unit;'):
        [(10, '72203100', 'probeTail', 'p0, p2')],
    (PACKAGE + 'EngineManager$State$Ready;', 'toString', f'(){STRING}'):
        [(18, '6e200100', 'append', 'v1, v0')],
    (PACKAGE + 'MainActivity$observeEngine$1$1;', 'emit',
     f'(Lcom/dsh/android/EngineManager$State;Lkotlin/coroutines/Continuation;){OBJECT}'):
        [(776, '6e20e300', 'append', 'v3, p2')],
    (PACKAGE + 'web/SystemWebHost;', 'reload', '()V'):
        [(48, '6e200100', 'append', 'v1, v0')],
}


def ref(owner, name, params, returned):
    return owner.encode(), name.encode(), tuple(param.encode() for param in params), returned.encode()


def sanitizing_calls(owned_ready=False):
    edits = {}
    for key, sites in SITES.items():
        edits[key] = {}
        for pc, encoded, wrapper, _ in sites:
            receiver, name, argument, returned, _ = WRAPPERS[wrapper]
            old = bytes.fromhex(encoded)
            edits[key][pc] = ((old, ref(receiver, name, (argument,), returned)),
                              (b'\x71' + old[1:], ref(OWNER, wrapper, (receiver, STRING), returned)))
    if owned_ready:
        edits[READER][294] = (
            (bytes.fromhex('71542d50'), ref(REGEX, 'find$default', (REGEX, CHARSEQ, 'I', 'I', OBJECT), MATCH)),
            (bytes.fromhex('71582d50'), ref(OWNER, 'findReady', (REGEX, CHARSEQ, 'I', 'I', PROCESS), MATCH)))
        for pc in (4656, 4732):
            edits[START][pc] = (
                (bytes.fromhex('71100000'), ref(ENGINE, 'access$get_state$p', (ENGINE,), FLOW)),
                (bytes.fromhex('71203000'), ref(OWNER, 'readyState', (ENGINE, STRING), FLOW)))
    return edits


def wrapper_key(wrapper):
    receiver, _, _, returned, _ = WRAPPERS[wrapper]
    return OWNER, wrapper, f'({receiver}{STRING}){returned}'


REDACT = (OWNER, 'publicLine', f'({STRING}){STRING}')
METHODS = {REDACT, *(wrapper_key(name) for name in WRAPPERS)}
READY_METHODS = {(OWNER, 'findReady', FIND_READY), (OWNER, 'readyState', f'({ENGINE}{STRING}){FLOW}')}
OWNED_START = (OWNER, 'startOwned', f'({PROCESS_BUILDER}{ENGINE}){PROCESS}')
OWNED_START_PC = 3912
OWNED_START_INVOKE = (bytes.fromhex('71202000'), ref(OWNER, 'startOwned', (PROCESS_BUILDER, ENGINE), PROCESS))


def wrapper_source(owned_ready=False, owner_bound=False):
    body = f'''.class public final {OWNER}
.super Ljava/lang/Object;

.method public static publicLine({STRING}){STRING}
    .locals 1
    if-eqz p0, :plain
    const-string v0, "token="
    invoke-virtual {{p0, v0}}, {STRING}->contains(Ljava/lang/CharSequence;)Z
    move-result v0
    if-eqz v0, :plain
    const-string v0, "{HIDDEN}"
    return-object v0
    :plain
    return-object p0
.end method
'''
    for wrapper, (receiver, name, argument, returned, mnemonic) in WRAPPERS.items():
        body += f'''
.method public static {wrapper}({receiver}{STRING}){returned}
    .locals 0
    invoke-static {{p1}}, {OWNER}->publicLine({STRING}){STRING}
    move-result-object p1
    {mnemonic} {{p0, p1}}, {receiver}->{name}({argument}){returned}
'''
        body += {'V': '    return-void\n', 'Z': '    move-result p0\n    return p0\n',
                 BUILDER: '    move-result-object p0\n    return-object p0\n'}[returned]
        body += '.end method\n'
    if owned_ready:
        body += f'''
.method public static findReady{FIND_READY}
    .locals 1
    invoke-static {{p4, p1}}, {STARTUP}->permitsVerifiedAnnouncement({PROCESS}{CHARSEQ})Z
    move-result v0
    if-eqz v0, :denied
    const/4 p4, 0x0
    invoke-static {{p0, p1, p2, p3, p4}}, {REGEX}->find$default{FIND}
    move-result-object v0
    return-object v0
    :denied
    const/4 v0, 0x0
    return-object v0
.end method

.method public static readyState({ENGINE}{STRING}){FLOW}
    .locals 1
    invoke-static {{p0}}, {ENGINE}->access$getProcess$p({ENGINE}){PROCESS}
    move-result-object v0
    invoke-static {{v0, p1}}, {STARTUP}->requireVerifiedReady({PROCESS}{STRING})V
    invoke-static {{p0}}, {ENGINE}->access$get_state$p({ENGINE}){FLOW}
    move-result-object v0
    return-object v0
.end method
'''
    if owner_bound:
        body += f'''
.method public static startOwned{OWNED_START[2]}
    .locals 0
    invoke-static {{p0, p1}}, {MAIN_HANDOFF}->claimOrDeny({PROCESS_BUILDER}{OBJECT}){PROCESS}
    move-result-object p0
    return-object p0
.end method
'''
    return body


def rewrite(key, source, sites, owned_ready=False, owner_bound=False):
    _, method, signature = key
    matches = list(re.finditer(r'^\.method [^\n]* ' + re.escape(method + signature)
                               + r'\n.*?^\.end method$', source, re.M | re.S))
    if len(matches) != 1:
        raise ValueError('STARTUP_DIAGNOSTICS_METHOD_ANCHOR')
    match = matches[0]
    body = match[0]
    anchors = Counter((wrapper, registers) for _, _, wrapper, registers in sites)
    for (wrapper, registers), count in anchors.items():
        receiver, name, argument, returned, mnemonic = WRAPPERS[wrapper]
        old = f'    {mnemonic} {{{registers}}}, {receiver}->{name}({argument}){returned}\n'
        new = f'    invoke-static {{{registers}}}, {OWNER}->{wrapper}({receiver}{STRING}){returned}\n'
        if key == START:
            # Other branches reuse these registers; select only the two Ready
            # log builders. The signed DEX check independently pins both PCs.
            ready = ('    const-string/jumbo v4, "\\u5f15\\u64ce\\u5c31\\u7eea: "\n\n'
                     f'    invoke-direct {{v2, v4}}, {BUILDER}-><init>({STRING})V\n\n')
            old, new = ready + old, ready + new
        if body.count(old) != count:
            raise ValueError('STARTUP_DIAGNOSTICS_INVOKE_ANCHOR')
        body = body.replace(old, new)
    if owner_bound and key == START:
        # v2 contains this$0 and remains live across ensureRescuePrompt().
        context = (f'    iget-object v2, v1, {START[0]}->this$0:{ENGINE}\n\n'
                   f'    invoke-static {{v2}}, {ENGINE}->access$ensureRescuePrompt({ENGINE})V\n')
        old = f'    invoke-static {{v0}}, {PACKAGE}p40/P40ProcessBridge;->start({PROCESS_BUILDER}){PROCESS}\n'
        new = f'    invoke-static {{v0, v2}}, {OWNER}->startOwned{OWNED_START[2]}\n'
        if body.count(context) != 1 or body.count(old) != 1:
            raise ValueError('OWNER_BOUND_ORIGINAL_SPAWN_ANCHOR')
        begin, finish = body.index(context) + len(context), body.index(old)
        if not re.fullmatch(r'\s*(?:\.line \d+\s+)?:try_start_\w+\s*', body[begin:finish]):
            raise ValueError('OWNER_BOUND_ORIGINAL_RECEIVER_DRIFT')
        body = body.replace(old, new)
    if owned_ready and key == READER:
        old = f'    invoke-static {{p5, v2, v0, v5, v4}}, {REGEX}->find$default{FIND}\n'
        new = f'    invoke-static {{p5, v2, v0, v5, p0}}, {OWNER}->findReady{FIND_READY}\n'
        if body.count(old) != 1:
            raise ValueError('OWNED_READY_ORIGINAL_REGEX_ANCHOR')
        body = body.replace(old, new)
    if owned_ready and key == START:
        old = (f'    invoke-static {{v0}}, {ENGINE}->access$get_state$p({ENGINE}){FLOW}\n\n'
               f'    move-result-object v0\n\n    new-instance v2, {ENGINE[:-1]}$State$Ready;\n')
        new = (f'    invoke-static {{v0, v3}}, {OWNER}->readyState({ENGINE}{STRING}){FLOW}\n\n'
               f'    move-result-object v0\n\n    new-instance v2, {ENGINE[:-1]}$State$Ready;\n')
        if body.count(old) != 2:
            raise ValueError('OWNED_READY_ORIGINAL_PUBLISH_ANCHOR')
        body = body.replace(old, new)
    return source[:match.start()] + body + source[match.end():]


def patch(original, root, owned_ready=False, owner_bound=False):
    owned_ready = owned_ready or owner_bound
    with original.open('rb') as apk:
        if hashlib.file_digest(apk, 'sha256').hexdigest() != ORIGINAL_SHA:
            raise ValueError('STARTUP_DIAGNOSTICS_SOURCE_APK_SHA')
    directory = root.resolve(strict=True) / 'smali'
    helper = directory / (OWNER[1:-1] + '.smali')
    if helper.exists() or helper.is_symlink() or directory not in helper.resolve().parents:
        raise ValueError('STARTUP_DIAGNOSTICS_NEW_HELPER_REQUIRED')
    changed = {}
    for key, sites in SITES.items():
        file = directory / (key[0][1:-1] + '.smali')
        if file.is_symlink() or directory not in file.resolve(strict=True).parents:
            raise ValueError('STARTUP_DIAGNOSTICS_SOURCE_PATH')
        source = changed[file] if file in changed else file.read_text(encoding='utf-8')
        changed[file] = rewrite(key, source, sites, owned_ready, owner_bound)
    helper.parent.mkdir(parents=True, exist_ok=True)
    with helper.open('x', encoding='utf-8') as output:
        output.write(wrapper_source(owned_ready, owner_bound))
    for file, source in changed.items():
        file.write_text(source, encoding='utf-8')
    print('ORIGINAL_STARTUP_DIAGNOSTICS_SCOPED_SMALI=PREPARED sites=9')
    if owned_ready:
        print('ORIGINAL_MAIN_OWNED_READY_SCOPED_SMALI=PREPARED sites=3')
    if owner_bound:
        print('ORIGINAL_MAIN_OWNER_BOUND_START_SMALI=PREPARED')


def verify_helper(strict, view, methods, owned_ready=False, owner_bound=False):
    """Verify executable instructions and resolved refs of all new methods."""
    classes = [cls for cls in view.dex.get_classes() if cls.get_name() == OWNER]
    strict.need(len(classes) == 1 and classes[0].get_access_flags() == 0x11 and
                classes[0].get_superclassname() == OBJECT and not classes[0].get_interfaces() and
                not classes[0].get_fields(), 'STARTUP_DIAGNOSTICS_HELPER_CLASS')

    def compare(key, inputs, expected, frame=None):
        method = methods[key]
        code = method.get_code()
        strict.need(method.get_access_flags() == 0x9 and code is not None and
                    (code.get_registers_size(), code.get_ins_size(), code.get_outs_size()) ==
                    (frame or (2, inputs, 2)) and
                    not strict.decode(method, view.dex)[1], 'STARTUP_DIAGNOSTICS_HELPER_FRAME')
        rows = view.rows(method)
        strict.validate_targets(rows)
        ordinals = {pc: i for i, pc in enumerate(rows)}
        actual = [strict.relocated_instruction(view, rows, ordinals, pc, raw) for pc, raw in rows.items()]
        strict.need(actual == expected, 'STARTUP_DIAGNOSTICS_HELPER_BODY')

    contains = ref(STRING, 'contains', ('Ljava/lang/CharSequence;',), 'Z')
    compare(REDACT, 1, [(b'\x38\x01', 7), (b'\x1a\x00', b'token='),
                        (b'\x6e\x20\x01\x00', contains), (b'\x0a\x00', None),
                        (b'\x38\x00', 7), (b'\x1a\x00', HIDDEN.encode()),
                        (b'\x11\x00', None), (b'\x11\x01', None)])
    redactor = ref(OWNER, 'publicLine', (STRING,), STRING)
    for wrapper, (receiver, name, argument, returned, mnemonic) in WRAPPERS.items():
        encoding = b'\x72' if mnemonic == 'invoke-interface' else b'\x6e'
        ending = {'V': [b'\x0e\x00'], 'Z': [b'\x0a\x00', b'\x0f\x00'],
                  BUILDER: [b'\x0c\x00', b'\x11\x00']}[returned]
        compare(wrapper_key(wrapper), 2,
                [(b'\x71\x10\x01\x00', redactor), (b'\x0c\x01', None),
                 (encoding + b'\x20\x10\x00', ref(receiver, name, (argument,), returned))]
                + [(raw, None) for raw in ending])
    if owned_ready:
        permits = ref(STARTUP, 'permitsVerifiedAnnouncement', (PROCESS, CHARSEQ), 'Z')
        find_default = ref(REGEX, 'find$default', (REGEX, CHARSEQ, 'I', 'I', OBJECT), MATCH)
        compare((OWNER, 'findReady', FIND_READY), 5,
                [(bytes.fromhex('71202500'), permits), (b'\x0a\x00', None), (b'\x38\x00', 7),
                 (b'\x12\x05', None), (bytes.fromhex('71552143'), find_default),
                 (b'\x0c\x00', None), (b'\x11\x00', None), (b'\x12\x00', None), (b'\x11\x00', None)],
                frame=(6, 5, 5))
        get_process = ref(ENGINE, 'access$getProcess$p', (ENGINE,), PROCESS)
        get_state = ref(ENGINE, 'access$get_state$p', (ENGINE,), FLOW)
        require = ref(STARTUP, 'requireVerifiedReady', (PROCESS, STRING), 'V')
        compare((OWNER, 'readyState', f'({ENGINE}{STRING}){FLOW}'), 2,
                [(bytes.fromhex('71100100'), get_process), (b'\x0c\x00', None),
                 (bytes.fromhex('71202000'), require), (bytes.fromhex('71100100'), get_state),
                 (b'\x0c\x00', None), (b'\x11\x00', None)], frame=(3, 2, 2))
    if owner_bound:
        handoff = ref(MAIN_HANDOFF, 'claimOrDeny', (PROCESS_BUILDER, OBJECT), PROCESS)
        compare(OWNED_START, 2, [(bytes.fromhex('71201000'), handoff),
                                (b'\x0c\x00', None), (b'\x11\x00', None)])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('decoded', type=Path)
    parser.add_argument('--owned-ready', action='store_true')
    parser.add_argument('--owner-bound', action='store_true')
    args = parser.parse_args()
    patch(args.original, args.decoded, args.owned_ready, args.owner_bound)
