#!/usr/bin/env python3
"""Pinned Android plugin source capsules outside engine.bin.

Provenance only: no launcher, owner permission, root tool grant, arbitrary
host-file reader or installed-DSH data access. Each archive keeps its own
origin namespace; equal package names MUST NOT collapse different versions.
This selected source set excludes other native/tool assets and generated YAML;
it does not establish the complete production Android dependency closure.
"""
import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
import zipfile

APK_SHA='3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
# ZIP size/hash/member count/uncompressed bytes/root package name/version.
ARCHIVES={
 'agnes-multimodal.zip':(32369,'7855b630c0a85fe12c416d520efa7aa924a201d5e5db2e4e5351d9d7a6f9f853',4,97496,'dsh-agnes-multimodal','1.0.0'),
 'browser-pane.zip':(14501,'87066b836f6c0d9396520b011eacd918e11ecf6323a9a17709e58287a175e377',4,36846,'dsh-android-browser-pane','1.0.0'),
 'browser-tool.zip':(313703,'807c49020a2b5cc1b99a15b12c4eabefb906754e329dfda45a1d964d15ac203a',6,792921,'dsh-android-browser','1.3.5'),
 'bubble-tool.zip':(28743,'f81bf7ba1bd9ef640da9a4d72af84550b8ef2ee389f09f88d3b4581a198488eb',2,78036,'dsh-android-bubble','1.0.0'),
 'logs-tool.zip':(11498,'3e6f281da126b2483d812c11297dd27d41787c29bbe3583221697749c39ff01a',2,24688,'dsh-android-logs','1.0.0'),
 'market-plugin.zip':(27007,'e242cec4ff57a246307f74946a0e8dca095e2ebcce8b4377118a71d0feba0b2b',5,69488,'dsh-android-market','1.0.0'),
 'mobile-ui.zip':(269232,'8a7bcd8884d8e71c6359d574c19d4547b57df841f13d415e22ae92a026b99e03',4,638030,'dsh-android-mobile','1.0.0'),
 'pet-bridge.zip':(5302,'c93b2671840a40695c8c8532140698df3e6366ec53e61badaf9f721a91c08568',2,9879,'dsh-android-pet','1.0.0'),
 'root-tool.zip':(6573,'d67301442216463dcf340d5c549b203d9c5ec3a7ebb07e8d25c54f1af24b95c1',2,12978,'dsh-android-root','1.0.0'),
 'statusbar-tool.zip':(12539,'8b8f66cd7fc322983c9a107fd2395226b34ceb460889359a5d4bbf6bc572dee8',2,30178,'dsh-android-statusbar','1.0.0'),
 'uiagent-tool.zip':(29251,'fde6902f63fee0778d4cc75ff449e58b977fb95bac9be57555351fb80eb26098',3,72540,'dsh-android-uiagent','1.0.0'),
}
RAW={
 'dsh-fetch-guard.mjs':(10546,'d1dbf181547fa8a9bdc1a73627b85e11f5fd5b8fe37f493ad5fb021b4794531e'),
 'linkcompat.bin':(10544,'89fbb44c3c3413761ba8e600f74b3d753ceae1895f0bba16a4288fda7305a423'),
}
NESTED_PACKAGES={
 'payload/mobile-ui/package.json':('dsh-android-mobile','1.3.5'),
 'payload/market/package.json':('dsh-android-market','1.3.5'),
}
MAX_FILE=8*1024*1024
MAX_TOTAL=16*1024*1024


def require(value,code):
    if not value:raise ValueError('ANDROID_SOURCE_'+code)


def sha(data):return hashlib.sha256(data).hexdigest()


def _path(value,directory=False):
    require(isinstance(value,str) and value and len(value.encode('utf-8'))<=4096,'PATH')
    require(value.isascii() and '\\' not in value and ':' not in value and
            not any(ord(c)<32 or ord(c)==127 for c in value),'PATH')
    name=value[:-1] if directory and value.endswith('/') else value
    parts=name.split('/')
    require(not name.startswith('/') and len(parts)<=64 and all(p and p not in ('.','..') and len(p)<=255 for p in parts),'PATH')
    require(str(PurePosixPath(name))==name,'PATH')
    return name


def _pairs(rows):
    value={}
    for key,item in rows:
        require(key not in value,'PACKAGE_DUPLICATE_KEY');value[key]=item
    return value


def _package(data):
    try:obj=json.loads(data.decode('utf-8'),object_pairs_hook=_pairs)
    except (UnicodeDecodeError,json.JSONDecodeError):raise ValueError('ANDROID_SOURCE_PACKAGE_JSON') from None
    require(isinstance(obj,dict) and isinstance(obj.get('name'),str) and
            re.fullmatch(r'(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+',obj['name']) is not None and
            isinstance(obj.get('version'),str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9_.-]+)?',obj['version']) is not None,'PACKAGE_IDENTITY')
    dependencies={}
    for field in ('dependencies','peerDependencies','optionalDependencies'):
        row=obj.get(field,{})
        require(isinstance(row,dict) and all(isinstance(k,str) and isinstance(v,str) and 0<len(k)<=256 and len(v)<=256 for k,v in row.items()),'PACKAGE_DEPENDENCIES')
        dependencies[field]=dict(row)
    return {'name':obj['name'],'version':obj['version'],**dependencies}


def _inspect_zip(blob):
    """Structural parser only; NOT a provenance or runtime admission API."""
    require(isinstance(blob,bytes) and len(blob)<=MAX_TOTAL,'ZIP_BOUND')
    files={};directories=set();packages={};total=0
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            entries=archive.infolist();require(0<len(entries)<=4096,'MEMBER_COUNT')
            for entry in entries:
                directory=entry.is_dir();name=_path(entry.filename,directory)
                require(name not in files and name not in directories,'DUPLICATE_PATH')
                kind=stat.S_IFMT(entry.external_attr>>16)
                require(kind in ((0,stat.S_IFDIR) if directory else (0,stat.S_IFREG)) and
                        not entry.flag_bits&1 and entry.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),'MEMBER_TYPE')
                require(0<=entry.file_size<=MAX_FILE and (not directory or entry.file_size==0),'MEMBER_SIZE')
                total+=entry.file_size;require(total<=MAX_TOTAL,'TOTAL_BOUND')
                if directory:directories.add(name);continue
                value=archive.read(entry);require(len(value)==entry.file_size,'MEMBER_LENGTH')
                require(not value.startswith((b'\x7fELF',b'MZ',b'dex\n',b'\xca\xfe\xba\xbe',b'\xfe\xed\xfa\xce',b'\xcf\xfa\xed\xfe')) and
                        not name.endswith(('.node','.so','.dex','.apk','.exe','.dll','.sh','.bat','.cmd','.ps1')),'NATIVE_PAYLOAD')
                files[name]=value
                if name=='package.json' or name.endswith('/package.json'):packages[name]=_package(value)
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError):raise ValueError('ANDROID_SOURCE_ZIP_FORMAT') from None
    require('package.json' in packages,'ROOT_PACKAGE')
    for name in [*files,*directories]:
        for parent in PurePosixPath(name).parents:
            if str(parent)!='.':require(str(parent) not in files,'PARENT_IS_FILE')
    return files,packages,total,len(entries)


@dataclass(frozen=True)
class VerifiedArchive:
    origin: str
    archive_sha256: str
    files: object
    packages: object

    def metadata(self):
        return {'origin':self.origin,'archive_sha256':self.archive_sha256,
                'files':{name:{'bytes':len(data),'sha256':sha(data),'type':'regular-source-data'} for name,data in sorted(self.files.items())},
                'packages':{name:dict(row) for name,row in self.packages.items()},
                'execution_authority':'NOT_GRANTED','dependency_resolution':'REQUIRES_OWNER_LAUNCH_PLAN'}


def verified_archive(name,blob):
    require(name in ARCHIVES,'ARCHIVE_NOT_ALLOWED')
    length,digest,count,total,package,version=ARCHIVES[name]
    require(isinstance(blob,bytes) and len(blob)==length and sha(blob)==digest,'ARCHIVE_SEAL')
    files,packages,size,members=_inspect_zip(blob)
    require(size==total and members==count,'ARCHIVE_CENSUS')
    expected={'package.json':(package,version)}
    if name=='browser-tool.zip':expected.update(NESTED_PACKAGES)
    require(set(packages)==set(expected) and all((packages[path]['name'],packages[path]['version'])==identity for path,identity in expected.items()),'PACKAGE_VERSION_SET')
    # Bytes remain immutable and every origin keeps its own package namespace.
    sealed_packages={path:MappingProxyType({k:MappingProxyType(v) if isinstance(v,dict) else v for k,v in row.items()}) for path,row in packages.items()}
    return VerifiedArchive(name,digest,MappingProxyType(files),MappingProxyType(sealed_packages))


def verified_sources(apk):
    apk=Path(apk)
    # Hash and ZIP reads use the SAME opened regular inode. A path replacement
    # after hashing must never substitute another APK for the verified source.
    descriptor=os.open(apk,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,'rb') as file:
        require(stat.S_ISREG(os.fstat(file.fileno()).st_mode),'APK_TYPE')
        require(hashlib.file_digest(file,'sha256').hexdigest()==APK_SHA,'APK_SHA')
        file.seek(0)
        with zipfile.ZipFile(file) as source:
            names=source.namelist();require(len(names)==len(set(names)),'APK_DUPLICATE_MEMBERS')
            archives={name:verified_archive(name,source.read('assets/'+name)) for name in ARCHIVES}
            raw={}
            for name,(length,digest) in RAW.items():
                entry=source.getinfo('assets/'+name);data=source.read(entry)
                require(not entry.is_dir() and stat.S_IFMT(entry.external_attr>>16) in (0,stat.S_IFREG) and
                        len(data)==length and sha(data)==digest,'RAW_ASSET_SEAL')
                raw[name]=data
    return MappingProxyType(archives),MappingProxyType(raw)


def stage_sources(apk,destination):
    """Build-only readonly source capsule in a NEW caller-owned directory.
    No extraction into installed app/profile paths; no symlink/executable or
    module activation. A manifest is written last, so partial output is unsealed.
    """
    archives,raw=verified_sources(apk)
    root=Path(destination).absolute()
    require(not root.exists() and not root.is_symlink() and root.parent==root.parent.resolve(),'NEW_CANONICAL_DESTINATION')
    manifest={'source_apk_sha256':APK_SHA,'execution_authority':'NOT_GRANTED',
              'archives':{name:archive.metadata() for name,archive in archives.items()},
              'raw':{name:{'bytes':len(data),'sha256':sha(data),'type':'opaque-original-preload-data'} for name,data in raw.items()}}
    # Walk with directory descriptors and NOFOLLOW. A swapped parent pathname
    # or nested symlink cannot redirect extraction into arbitrary host files.
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    parent=os.open('/',flags)
    try:
        for component in root.parent.parts[1:]:
            child=os.open(component,flags,dir_fd=parent);os.close(parent);parent=child
        os.mkdir(root.name,mode=0o700,dir_fd=parent)
        directory=os.open(root.name,flags,dir_fd=parent)
    finally:os.close(parent)
    def write(relative,data):
        parts=_path(relative).split('/');folder=os.dup(directory)
        try:
            for component in parts[:-1]:
                try:os.mkdir(component,mode=0o700,dir_fd=folder)
                except FileExistsError:pass
                child=os.open(component,flags,dir_fd=folder);os.close(folder);folder=child
            fd=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,dir_fd=folder)
            with os.fdopen(fd,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())
        finally:os.close(folder)
    try:
        for name,archive in archives.items():
            for path,data in archive.files.items():write('archives/'+name+'/'+path,data)
        for name,data in raw.items():write('raw/'+name,data)
        write('SOURCE-MANIFEST.json',json.dumps(manifest,sort_keys=True,separators=(',',':'),default=dict).encode()+b'\n')
    finally:os.close(directory)
    return manifest


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('apk',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.output:metadata=stage_sources(args.apk,args.output)
    else:
        archives,raw=verified_sources(args.apk)
        metadata={'archives':{name:archive.metadata() for name,archive in archives.items()},'raw_members':len(raw),'execution_authority':'NOT_GRANTED'}
    print('ORIGINAL_ANDROID_ASSET_ARCHIVES=VERIFIED count='+str(len(metadata['archives'])))
    print('ORIGINAL_ANDROID_MODULE_ADMISSION_AND_ENGINE_MANAGER=NOT_AUTHORIZED')
