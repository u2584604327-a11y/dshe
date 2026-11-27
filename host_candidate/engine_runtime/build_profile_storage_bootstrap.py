#!/usr/bin/env python3
"""Actual original JSON storage integration. No main/EngineManager authority."""
import argparse
import hashlib
from pathlib import Path
from build_http_bootstrap import CORE,CORE_SHA,ROOT,once
from build_profile_transport import build as profile_transport


def wrapped(file,exports,imports):
    source=(ROOT/file).read_text()
    for line in imports:source=once(source,line+'\n','')
    for name in exports:source=once(source,'export function '+name,'function '+name)
    return 'const {'+','.join(exports)+'}=(()=>{\n'+source+'\nreturn {'+','.join(exports)+'};})();\n'


def build():
    raw=CORE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=CORE_SHA:raise RuntimeError('PROFILE_STORAGE_RESOURCE_CORE_SHA')
    prefix,run=raw.decode().split('async function run() {\n')
    prefix=once(prefix,"!== 'DSHMOD01'","!== 'DSHMOD02'")
    prefix=once(prefix,'  const trailing = Buffer.alloc(1);\n','')
    prefix=once(prefix,'if (streamRead(trailing, 0, 1) !== 0 || members','if (members')
    setup=run.split("  const mode = process.env.DSH_ORIGINAL_CONFIG_MODE",1)[0]
    hooks=once(once(setup,'  receiveModules();\n',''),'  installReadonlyFilesystem();\n','')
    transport=profile_transport().decode()
    transport=once(once(transport,"import fs from 'node:fs';\n",''),"import {createHash} from 'node:crypto';\n",'')
    transport=once(transport,'export async function installProfileTransport','async function installProfileTransport')
    codec=wrapped('session_snapshot.mjs',['decodeSessionSnapshot','encodeSessionSnapshot'],["import path from 'node:path';"])
    filesystem=wrapped('session_filesystem.mjs',['installSessionFilesystem'],["import fs from 'node:fs';","import path from 'node:path';","import {randomBytes} from 'node:crypto';","import {syncBuiltinESMExports} from 'node:module';","import {decodeSessionSnapshot,encodeSessionSnapshot} from './session_snapshot.mjs';"])
    directory=once((ROOT/'readonly_directory.mjs').read_text(),'export function installVirtualDirectories','function installVirtualDirectories')
    entry=once((ROOT/'test/original_profile_storage_entry.mjs').read_text(),'  // INSERT_ORIGINAL_MODULE_HOOKS',hooks)
    return (prefix+"\nimport {randomBytes} from 'node:crypto';\n"+transport+codec+filesystem+directory+entry).encode()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path)
    args=parser.parse_args();args.output.write_bytes(build())
