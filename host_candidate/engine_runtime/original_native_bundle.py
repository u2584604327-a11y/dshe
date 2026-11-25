#!/usr/bin/env python3
"""Stage the original Android require-builtin supplement; never load/execute it.

EngineManager.ensureNativeAddon installs this archive outside engine.bin. Its
four files belong to a separate pinned closure. The public stager checks all
inputs before creating an output and rejects incompatible device page sizes.
It does not authorize P47, register a dlopen hook or alter the config bootstrap.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import zipfile

APK_SHA = '3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
ARCHIVE = 'assets/node-addon-android-arm64.zip'
ARCHIVE_SHA = '37351527c134cc6b5011b81382b28233b5f4694600d226b21d96b35654a2e92e'
PACKAGE = 'node-addon-require-builtin-android-arm64'
MEMBERS = {
    'index.js': (128, 'b0f0f140e07303b7104192db9f8791a1e057b2a974934dcc7415fd9aff2f79e8'),
    'package.json': (429, 'e748d9d530986a873b80befa97de55b67f7ee09c1afdb0e53475111907ca762e'),
    'prebuilds.json': (221, '8fbaec402a97f535675abb10fd8b9f76eb7beb29449518fb7f00894abe0093e6'),
    'prebuilt/android-arm64-napi-v9.node': (91840, 'b69021cecbe48a62395b6a30c4975d17c4277ccb2429adada78dd74bc0fb0c44'),
}
NATIVE = 'prebuilt/android-arm64-napi-v9.node'
ALIAS = 'libdsh_original_require_builtin.so'
CXX_SHA = 'e09c2f45cf4cf8ae574f94b6c2650d99ead0d332d5396f6613f062a2d2d73540'


def require(value, code):
    if not value:
        raise ValueError(code)


def sealed_members(archive):
    entries = archive.infolist()
    require(len(entries) == len(MEMBERS) and {x.filename for x in entries} == set(MEMBERS),
            'ADDON_MEMBER_SET')
    result = {}
    for entry in entries:
        size, digest = MEMBERS[entry.filename]
        mode = entry.external_attr >> 16
        require(not entry.is_dir() and (stat.S_IFMT(mode) in (0, stat.S_IFREG)) and
                not entry.flag_bits & 1 and entry.file_size == size, 'ADDON_MEMBER_TYPE_LENGTH')
        data = archive.read(entry)
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, 'ADDON_MEMBER_SHA')
        result[entry.filename] = data
    package = json.loads(result['package.json'])
    require(package['name'] == PACKAGE and package['version'] == '0.1.7' and
            package['os'] == ['android'] and package['cpu'] == ['arm64'] and
            package['dependencies'] == {'node-addon-native-custom-loader': '0.1.7'}, 'ADDON_VERSION')
    prebuild = json.loads(result['prebuilds.json'])
    require(prebuild == {'platform': 'android-arm64', 'binaries': [{
        'backend': 'napi', 'abi': 'napi-v9', 'binaryTag': 'napi-v9',
        'node': '>=20', 'path': NATIVE}]}, 'ADDON_PREBUILD')
    return result


def elf_layout(data, page_size):
    """Bounded ELF64 program/dynamic-table checks, without running readelf."""
    require(page_size in (4096, 16384), 'ADDON_DEVICE_PAGE_SIZE')
    require(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and
            struct.unpack_from('<HHI', data, 16) == (3, 183, 1), 'ADDON_ELF_IDENTITY')
    offset = struct.unpack_from('<Q', data, 32)[0]
    width, count = struct.unpack_from('<HH', data, 54)
    require(width == 56 and 0 < count <= 64 and offset + width * count <= len(data), 'ADDON_ELF_HEADERS')
    rows = [struct.unpack_from('<IIQQQQQQ', data, offset + width * n) for n in range(count)]
    loads = [r for r in rows if r[0] == 1]
    require(loads and not any(r[0] == 3 for r in rows), 'ADDON_ELF_LOAD_OR_INTERPRETER')
    for _, flags, file_offset, virtual, _, size, memory, alignment in loads:
        require(size <= memory and file_offset + size <= len(data) and flags & 3 != 3 and
                alignment >= 4096 and alignment & (alignment - 1) == 0 and
                file_offset % alignment == virtual % alignment, 'ADDON_ELF_SEGMENT')
        require(alignment >= page_size and file_offset % page_size == virtual % page_size,
                'ADDON_ORIGINAL_ELF_PAGE_SIZE_INCOMPATIBLE')
    dynamic = [r for r in rows if r[0] == 2]
    require(len(dynamic) == 1, 'ADDON_ELF_DYNAMIC')
    row = dynamic[0]
    require(row[5] % 16 == 0 and row[2] + row[5] <= len(data), 'ADDON_ELF_DYNAMIC_BOUND')
    tags = []
    for at in range(row[2], row[2] + row[5], 16):
        tag, value = struct.unpack_from('<qQ', data, at)
        tags.append((tag, value))
        if tag == 0:
            break
    require(tags and tags[-1][0] == 0, 'ADDON_ELF_DYNAMIC_TERMINATOR')
    def singleton(tag):
        values = [value for kind, value in tags if kind == tag]
        require(len(values) == 1, 'ADDON_ELF_DYNAMIC_SINGLETON')
        return values[0]
    address, size = singleton(5), singleton(10)
    spans = [r[2] + address - r[3] for r in loads if r[3] <= address and address + size <= r[3] + r[5]]
    require(len(spans) == 1 and size <= 65536, 'ADDON_ELF_STRING_TABLE')
    table = data[spans[0]:spans[0] + size]
    needed = []
    for tag, value in tags:
        require(tag not in (15, 29), 'ADDON_ELF_SEARCH_PATH')
        if tag != 1:
            continue
        require(value < len(table), 'ADDON_ELF_NEEDED_STRING')
        end = table.find(b'\0', value)
        require(end >= value, 'ADDON_ELF_NEEDED_STRING')
        needed.append(table[value:end].decode('ascii'))
    require(sorted(needed) == ['libc++_shared.so', 'libc.so', 'libdl.so', 'libm.so'], 'ADDON_ELF_DEPENDENCIES')
    return needed


def verified_bundle(apk):
    with Path(apk).open('rb') as source:
        require(hashlib.file_digest(source, 'sha256').hexdigest() == APK_SHA, 'ADDON_SOURCE_APK_SHA')
    with zipfile.ZipFile(apk) as outer:
        require(len(outer.namelist()) == len(set(outer.namelist())), 'ADDON_SOURCE_DUPLICATE')
        info = outer.getinfo(ARCHIVE)
        require(info.file_size == 37526, 'ADDON_ARCHIVE_LENGTH')
        payload = outer.read(info)
        require(hashlib.sha256(payload).hexdigest() == ARCHIVE_SHA, 'ADDON_ARCHIVE_SHA')
        with zipfile.ZipFile(io.BytesIO(payload)) as inner:
            files = sealed_members(inner)
        # The Node runtime already provides this exact dependency through P49.
        info = outer.getinfo('assets/bootstrap-aarch64.zip')
        require(info.file_size <= 80 * 1024 * 1024, 'ADDON_CXX_ARCHIVE_BOUND')
        with zipfile.ZipFile(io.BytesIO(outer.read(info))) as bootstrap:
            matches = [x for x in bootstrap.infolist() if x.filename == 'lib/libc++_shared.so']
            require(len(matches) == 1 and matches[0].file_size == 1374336, 'ADDON_CXX_LENGTH')
            cxx = bootstrap.read(matches[0])
            require(hashlib.sha256(cxx).hexdigest() == CXX_SHA, 'ADDON_CXX_SHA')
    return files


def stage(apk, output, page_size):
    files = verified_bundle(apk)
    dependencies = elf_layout(files[NATIVE], page_size)
    manifest = {
        'source_apk_sha256': APK_SHA, 'source_archive': ARCHIVE,
        'source_archive_sha256': ARCHIVE_SHA, 'package': PACKAGE, 'version': '0.1.7',
        'required_page_size': page_size, 'native_alias': ALIAS,
        'native_virtual_path': '/dsh-runtime/node_modules/' + PACKAGE + '/' + NATIVE,
        'native_sha256': MEMBERS[NATIVE][1], 'dependencies': dependencies,
        'members': {name: {'size': size, 'sha256': digest} for name, (size, digest) in MEMBERS.items()},
        'existing_p49_cxx_sha256': CXX_SHA,
        'runtime_binding': 'NOT_TESTED', 'production_supervisor': 'NOT_AUTHORIZED',
    }
    # Fixed flat names only. Never follow a preexisting directory/file/link,
    # install into an app, execute, or modify a supplied resource/package.
    output = Path(output)
    os.mkdir(output, 0o700)
    directory = os.open(output, os.O_DIRECTORY | os.O_NOFOLLOW)
    created = []
    try:
        payloads = {ALIAS: files[NATIVE], **{name: data for name, data in files.items() if name != NATIVE},
                    'native-resource.json': (json.dumps(manifest, sort_keys=True) + '\n').encode()}
        for name, data in payloads.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=directory)
            created.append(name)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for name in created:
            os.unlink(name, dir_fd=directory)
        os.rmdir(output)
        raise
    finally:
        os.close(directory)
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--device-page-size', type=int, choices=(4096, 16384), required=True)
    args = parser.parse_args()
    stage(args.apk, args.output, args.device_page_size)
    print('ORIGINAL_ANDROID_ADDON_SOURCE_CLOSURE_AND_STAGE=PASS_STATIC')
    print('ORIGINAL_ANDROID_ADDON_DLOPEN_AND_FULL_ENGINE=NOT_TESTED')
