#!/usr/bin/env python3
"""Install only the verified original supplement into a disposable decoded APK."""
import argparse
from pathlib import Path
import zipfile
import original_native_bundle as bundle
from build_native_http_bootstrap import build


def prepare(apk, decoded):
    files = bundle.verified_bundle(apk)
    bundle.elf_layout(files[bundle.NATIVE], 4096)
    script = build(apk)
    target = decoded / 'assets/engine-http-services.mjs'
    if not target.parent.is_dir():
        raise ValueError('ADDON_DECODED_DIRECTORY')
    if target.exists() or target.is_symlink():
        raise ValueError('ADDON_DECODED_COLLISION')
    # Fixed destination names; never extract an untrusted ZIP path.
    with target.open('xb') as output:
        output.write(script)
    print('ORIGINAL_ANDROID_ADDON_FIXED_INSTALLER_ALIAS_AND_BOOTSTRAP=PASS_STATIC')
    print('ORIGINAL_ANDROID_ADDON_ACTUAL_DLOPEN_AND_MAIN=NOT_TESTED')


def embed(apk, candidate):
    files = bundle.verified_bundle(apk)
    bundle.elf_layout(files[bundle.NATIVE], 4096)
    name = 'lib/arm64-v8a/' + bundle.ALIAS
    with zipfile.ZipFile(candidate, 'a') as output:
        names = output.namelist()
        if len(names) != len(set(names)) or name in names:
            raise ValueError('ADDON_APK_NATIVE_COLLISION')
        # Append before the existing alignment/signing steps. No apktool
        # compression default can silently turn this into a compressed ELF.
        output.writestr(name, files[bundle.NATIVE], compress_type=zipfile.ZIP_STORED)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['prepare', 'embed'])
    parser.add_argument('apk', type=Path)
    parser.add_argument('target', type=Path)
    args = parser.parse_args()
    (prepare if args.mode == 'prepare' else embed)(args.apk, args.target)
