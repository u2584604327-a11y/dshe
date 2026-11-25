#!/usr/bin/env python3
"""Exercise the real APK supplement and reject malformed packaging/ELF plans."""
import argparse
import copy
import hashlib
import io
import os
from pathlib import Path
import struct
import tempfile
import zipfile

import original_native_bundle as bundle


def denied(operation, code):
    try:
        operation()
    except ValueError as error:
        assert str(error) == code, (code, str(error))
    else:
        raise AssertionError('INVALID_NATIVE_BUNDLE_ACCEPTED_' + code)


def main(apk):
    files = bundle.verified_bundle(apk)
    assert bundle.elf_layout(files[bundle.NATIVE], 4096) == ['libc++_shared.so', 'libm.so', 'libdl.so', 'libc.so']
    denied(lambda: bundle.elf_layout(files[bundle.NATIVE], 16384),
           'ADDON_ORIGINAL_ELF_PAGE_SIZE_INCOMPATIBLE')
    denied(lambda: bundle.elf_layout(files[bundle.NATIVE], 8192), 'ADDON_DEVICE_PAGE_SIZE')
    with zipfile.ZipFile(apk) as source:
        raw = source.read(bundle.ARCHIVE)
    for kind, code in [('TRAVERSAL', 'ADDON_MEMBER_SET'), ('DUPLICATE', 'ADDON_MEMBER_SET'),
                       ('SYMLINK', 'ADDON_MEMBER_TYPE_LENGTH'), ('MUTATE', 'ADDON_MEMBER_SHA')]:
        memory = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(memory, 'w') as target:
            for entry in source.infolist():
                item = copy.copy(entry)
                data = source.read(entry)
                if entry.filename == 'index.js':
                    if kind == 'TRAVERSAL': item.filename = '../index.js'
                    elif kind == 'SYMLINK': item.create_system = 3; item.external_attr = 0o120777 << 16
                    elif kind == 'MUTATE': data = bytes([data[0] ^ 1]) + data[1:]
                target.writestr(item, data)
            if kind == 'DUPLICATE':
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    target.writestr('index.js', files['index.js'])
        with zipfile.ZipFile(memory) as archive:
            denied(lambda: bundle.sealed_members(archive), code)
    data = bytearray(files[bundle.NATIVE])
    struct.pack_into('<Q', data, 32, len(data) - 1)
    denied(lambda: bundle.elf_layout(data, 4096), 'ADDON_ELF_HEADERS')
    data = bytearray(files[bundle.NATIVE]); data[18:20] = (62).to_bytes(2, 'little')
    denied(lambda: bundle.elf_layout(data, 4096), 'ADDON_ELF_IDENTITY')
    with tempfile.TemporaryDirectory(prefix='original-native-closure-') as folder:
        root = Path(folder); output = root / 'staged'
        manifest = bundle.stage(apk, output, 4096)
        assert manifest['version'] == '0.1.7' and manifest['runtime_binding'] == 'NOT_TESTED'
        assert len(manifest['members']) == 4 and (output / bundle.ALIAS).read_bytes() == files[bundle.NATIVE]
        assert not (output / bundle.ALIAS).stat().st_mode & 0o222
        assert (output / 'index.js').read_bytes() == files['index.js']
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}
        try: bundle.stage(apk, output, 4096)
        except FileExistsError: pass
        else: raise AssertionError('PREEXISTING_NATIVE_STAGE_OVERWRITTEN')
        assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}
        incompatible = root / '16k'
        denied(lambda: bundle.stage(apk, incompatible, 16384), 'ADDON_ORIGINAL_ELF_PAGE_SIZE_INCOMPATIBLE')
        assert not incompatible.exists()
        link = root / 'link'; os.symlink(output, link)
        try: bundle.stage(apk, link, 4096)
        except FileExistsError: pass
        else: raise AssertionError('NATIVE_STAGE_FOLLOWED_LINK')
        assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir()}
    print('ORIGINAL_ANDROID_ADDON_FOUR_MEMBERS_AND_CXX_DEPENDENCY=PASS_STATIC')
    print('ORIGINAL_ANDROID_ADDON_BYTE_PRESERVING_STAGER_AND_NEGATIVES=PASS')
    print('ORIGINAL_ANDROID_ADDON_16K_PAGE_DEVICE=DENY_ORIGINAL_ELF_ALIGNMENT')
    print('ORIGINAL_ANDROID_ADDON_ACTUAL_DLOPEN_AND_MAIN_PROFILE=NOT_TESTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    main(parser.parse_args().apk)
