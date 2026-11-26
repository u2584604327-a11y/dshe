#!/usr/bin/env python3
"""Actual signed APK source checks plus malicious in-memory ZIP structure.
No Node/app execution or module authorization is asserted by these tests.
"""
import argparse
import errno
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import warnings
import zipfile
from unittest.mock import patch
import original_android_bundles as bundles


def require(value,code):
    if not value:raise AssertionError(code)


def archive(rows):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as out:
        for path,data,mode in rows:
            entry=zipfile.ZipInfo(path);entry.external_attr=mode<<16
            with warnings.catch_warnings():
                warnings.simplefilter('ignore',UserWarning);out.writestr(entry,data)
    return stream.getvalue()


def rejects(operation,reason):
    try:operation()
    except ValueError as failure:require(str(failure)=='ANDROID_SOURCE_'+reason,'WRONG_NEGATIVE_'+reason)
    else:raise AssertionError('ACCEPTED_'+reason)


def main(apk):
    archives,raw=bundles.verified_sources(apk)
    require(len(archives)==11 and sum(len(bundle.files) for bundle in archives.values())==33 and len(raw)==2,'ACTUAL_SOURCE_CENSUS')
    mobile=archives['mobile-ui.zip'].packages['package.json'];nested=archives['browser-tool.zip'].packages['payload/mobile-ui/package.json']
    market=archives['market-plugin.zip'].packages['package.json'];nested_market=archives['browser-tool.zip'].packages['payload/market/package.json']
    require(mobile['name']==nested['name'] and mobile['version']=='1.0.0' and nested['version']=='1.3.5','MOBILE_ORIGIN_VERSION_COLLISION_NOT_PRESERVED')
    require(market['name']==nested_market['name'] and market['version']=='1.0.0' and nested_market['version']=='1.3.5','MARKET_ORIGIN_VERSION_COLLISION_NOT_PRESERVED')
    try:archives['mobile-ui.zip'].files['bad']=b'bad'
    except TypeError:pass
    else:raise AssertionError('MUTABLE_VERIFIED_FILES')
    try:mobile['dependencies']['injected']='*'
    except TypeError:pass
    else:raise AssertionError('MUTABLE_VERIFIED_DEPENDENCIES')
    root=('package.json',b'{"name":"unit-source","version":"1.0.0"}',stat.S_IFREG|0o644)
    fixture=archive([root,('lib/index.js',b'export const source=1;',stat.S_IFREG|0o644)])
    files,packages,total,count=bundles._inspect_zip(fixture)
    require(set(files)=={'package.json','lib/index.js'} and count==2 and packages['package.json']['version']=='1.0.0','STRUCTURAL_POSITIVE')
    for path in ('../escape','/data/private','a/../b','a\\b','C:/drive','a//b','./b','a\x00b','a\x1fb','a\x7fb','x'*256):
        # ZipInfo itself truncates NUL; exercise the path validator directly.
        rejects(lambda path=path:bundles._path(path),'PATH')
    rejects(lambda:bundles._inspect_zip(archive([root,('link',b'/data/private',stat.S_IFLNK|0o777)])),'MEMBER_TYPE')
    rejects(lambda:bundles._inspect_zip(archive([root,('dir/',b'',stat.S_IFREG|0o644)])),'MEMBER_TYPE')
    rejects(lambda:bundles._inspect_zip(archive([root,root])),'DUPLICATE_PATH')
    rejects(lambda:bundles._inspect_zip(archive([root,('a',b'data',stat.S_IFREG|0o600),('a/b.js',b'1',stat.S_IFREG|0o600)])),'PARENT_IS_FILE')
    rejects(lambda:bundles._inspect_zip(archive([root,('lib/payload.js',b'\x7fELFbad',stat.S_IFREG|0o600)])),'NATIVE_PAYLOAD')
    rejects(lambda:bundles._inspect_zip(archive([root,('run.sh',b'echo unsafe',stat.S_IFREG|0o600)])),'NATIVE_PAYLOAD')
    rejects(lambda:bundles._inspect_zip(archive([('other.json',b'{}',stat.S_IFREG|0o600)])),'ROOT_PACKAGE')
    rejects(lambda:bundles._inspect_zip(archive([('package.json',b'{"name":"one","name":"two","version":"1.0.0"}',stat.S_IFREG|0o600)])),'PACKAGE_DUPLICATE_KEY')
    rejects(lambda:bundles.verified_archive('unknown.zip',fixture),'ARCHIVE_NOT_ALLOWED')
    with zipfile.ZipFile(apk) as source:
        original=source.read('assets/mobile-ui.zip');mutated=bytes([original[0]^1])+original[1:]
        rejects(lambda:bundles.verified_archive('mobile-ui.zip',mutated),'ARCHIVE_SEAL')
    with tempfile.TemporaryDirectory(prefix='dsh-android-source-') as temp:
        root_path=Path(temp);fake=root_path/'not-the-original.apk';fake.write_bytes(b'not-an-apk');output=root_path/'must-not-exist'
        rejects(lambda:bundles.stage_sources(fake,output),'APK_SHA');require(not output.exists(),'BAD_SOURCE_CREATED_DESTINATION')
        staged=root_path/'sources';manifest=bundles.stage_sources(apk,staged)
        for origin,bundle in archives.items():
            for path,value in bundle.files.items():
                file=staged/'archives'/origin/path
                require(file.read_bytes()==value and file.stat().st_mode&0o777==0o400,'STAGED_BYTES_OR_MODE')
        manifest_file=staged/'SOURCE-MANIFEST.json';record=json.loads(manifest_file.read_text())
        require(record['source_apk_sha256']==bundles.APK_SHA and record['execution_authority']=='NOT_GRANTED','PROVENANCE_IS_NOT_ACTIVATION')
        rejects(lambda:bundles.stage_sources(apk,staged),'NEW_CANONICAL_DESTINATION')
        # A real path swap after the hash must not substitute another inode
        # when the ZIP parser opens its input. No copy or mutation of v138.
        changing=root_path/'source.apk';os.link(apk,changing)
        digest=bundles.hashlib.file_digest
        def swap_after_hash(file,algorithm):
            result=digest(file,algorithm)
            changing.unlink();changing.write_bytes(b'foreign unverified apk')
            return result
        with patch.object(bundles.hashlib,'file_digest',side_effect=swap_after_hash):
            kept,_=bundles.verified_sources(changing)
            require(len(kept)==11,'APK_HASH_TO_READ_INODE_SWAP')
        # Replace a newly created internal directory with a symlink while
        # extracting. Directory-relative NOFOLLOW must refuse before writing.
        outside=root_path/'outside';outside.mkdir();racing=root_path/'racing'
        mkdir=bundles.os.mkdir
        def swap_directory(path,*args,**kwargs):
            mkdir(path,*args,**kwargs)
            if path=='archives' and 'dir_fd' in kwargs:
                os.rmdir(path,dir_fd=kwargs['dir_fd'])
                os.symlink(outside,path,dir_fd=kwargs['dir_fd'])
        with patch.object(bundles.os,'mkdir',side_effect=swap_directory):
            try:bundles.stage_sources(apk,racing)
            except OSError as failure:require(failure.errno in (errno.ELOOP,errno.ENOTDIR),'WRONG_STAGE_LINK_REJECTION')
            else:raise AssertionError('STAGE_FOLLOWED_SWAPPED_DIRECTORY')
        require(not list(outside.iterdir()) and not (racing/'SOURCE-MANIFEST.json').exists(),'FAILED_STAGE_ESCAPED_OR_SEALED')
    print('ORIGINAL_ANDROID_EXTRA_ARCHIVES_AND_PRELOADS=PASS_SOURCE_ONLY archives=11 files=33 raw=2')
    print('ORIGINAL_ANDROID_NESTED_MOBILE_MARKET_VERSION_ORIGINS=PASS_1_3_5_AND_1_0_0')
    print('ORIGINAL_ANDROID_SOURCE_PATH_TYPE_HASH_DUPLICATE_AND_NATIVE_NEGATIVES=PASS')
    print('ORIGINAL_ANDROID_SOURCE_HASH_READ_INODE_SWAP_AND_STAGE_SYMLINK_RACE=PASS')
    print('ORIGINAL_ANDROID_SUPPLEMENT_PRODUCTION_OWNER_AND_MODULE_ADMISSION=NOT_AUTHORIZED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('apk',type=Path);args=parser.parse_args();main(args.apk)
