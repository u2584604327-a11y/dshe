#!/usr/bin/env python3
"""Create the fixed supplement adapter from the verified original APK.

This is a runtime building block, not an enabled main profile, an arbitrary
module mapper or a P47 registration. No APK or signing operation occurs here.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import original_native_bundle as bundle

ROOT = Path(__file__).resolve().parent


def build(apk):
    files = bundle.verified_bundle(apk)
    bundle.elf_layout(files[bundle.NATIVE], 4096)
    adapter = (ROOT / 'original_native_mapping.mjs').read_text()
    marker = 'export function installOriginalAndroidNativeMapping'
    if adapter.count(marker) != 1:
        raise ValueError('ADDON_MAPPING_SOURCE_ANCHOR')
    adapter = adapter.replace(marker, 'function installOriginalAndroidNativeMapping')
    for declaration in ["import fs from 'node:fs';\n", "import path from 'node:path';\n",
                        "import {createHash} from 'node:crypto';\n"]:
        if adapter.count(declaration) != 1:
            raise ValueError('ADDON_MAPPING_IMPORT_ANCHOR')
        adapter = adapter.replace(declaration, '')
    metadata = ',\n'.join(json.dumps(name) + ': Buffer.from(' +
                         json.dumps(base64.b64encode(files[name]).decode()) + ', "base64")'
                         for name in bundle.MEMBERS if name != bundle.NATIVE)
    # The surrounding bootstrap owns files/directories and pageSize. It must
    # compose this before installReadonlyFilesystem, and use the returned
    # nativeMapping.format/source only at its explicit resolve/load seams.
    return ('const nativeMapping = (() => {\n' + adapter +
            '\nreturn installOriginalAndroidNativeMapping(\n'
            '  files, directories, {\n' + metadata + '\n  }, pageSize);\n})();\n').encode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    payload = build(args.apk)
    # No overwriting an existing artifact or following a caller-supplied link.
    with args.output.open('xb') as output:
        output.write(payload)
    print('ORIGINAL_ANDROID_ADDON_FIXED_OVERLAY_SHA256=' + hashlib.sha256(payload).hexdigest())
    print('ORIGINAL_ANDROID_ADDON_RUNTIME_AND_MAIN_PROFILE=NOT_TESTED')
