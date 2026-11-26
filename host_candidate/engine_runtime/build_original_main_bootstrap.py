#!/usr/bin/env python3
"""Compose the full original fresh-web main, without registering a supervisor.
Only verified resources, fixed native mapping and explicit owner snapshots.
EngineManager argument parity/profile authority and Android execution are
independent release gates; this is not an enabled production P47 backend.
"""
import argparse
import hashlib
from pathlib import Path
from build_http_bootstrap import CORE,CORE_SHA,ROOT,once
from build_profile_transport import build as profile_transport
from build_profile_storage_bootstrap import wrapped
from build_native_overlay import build as native_overlay


def build(apk):
    raw=CORE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=CORE_SHA:raise RuntimeError('MAIN_RESOURCE_CORE_SHA')
    prefix,run=raw.decode().split('async function run() {\n')
    prefix=once(prefix,"!== 'DSHMOD01'","!== 'DSHMOD02'")
    prefix=once(prefix,'  const trailing = Buffer.alloc(1);\n','')
    prefix=once(prefix,'if (streamRead(trailing, 0, 1) !== 0 || members','if (members')
    hooks=run.split("  const mode = process.env.DSH_ORIGINAL_CONFIG_MODE",1)[0]
    hooks=once(once(hooks,'  receiveModules();\n',''),'  installReadonlyFilesystem();\n','')
    if hooks.count('format: formatOf(filename)')!=2:raise RuntimeError('MAIN_NATIVE_FORMAT_SEAM')
    hooks=hooks.replace('format: formatOf(filename)','format: nativeMapping.format(filename) ?? formatOf(filename)')
    hooks=once(hooks,'      const source = files.get(filename);','      const source = nativeMapping.source(filename) ?? files.get(filename);')
    transport=profile_transport().decode()
    transport=once(once(transport,"import fs from 'node:fs';\n",''),"import {createHash} from 'node:crypto';\n",'')
    transport=once(transport,'export async function installProfileTransport','async function installProfileTransport')
    transport=once(transport,'onFailure = () => {}} = {}) {','onFailure = () => {}, originalDefaultPort} = {}) {')
    transport=once(transport,'  const requestedPort = hello.readUInt32BE(80), port = hello.readUInt32BE(84);',
        '''  const wirePort = hello.readUInt32BE(80), port = hello.readUInt32BE(84);
  const omitPort = (wirePort & 65536) !== 0, workspaceOverlay = (wirePort & 131072) !== 0;
  const explicitPort = wirePort & 65535;
  const requestedPort = omitPort ? originalDefaultPort : explicitPort;''')
    transport=once(transport,'      requestedPort > 65535 || port < 1',
        '      wirePort > 262143 || !Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535 ||\n'
        '      (omitPort && (explicitPort !== 0 || requestedPort === 0)) || port < 1')
    transport=once(transport,'    port, requestedPort, reading,',
        '    port, requestedPort, omitPort, workspaceOverlay, reading,')
    codec=wrapped('session_snapshot.mjs',['decodeSessionSnapshot','encodeSessionSnapshot'],["import path from 'node:path';"])
    filesystem=wrapped('session_filesystem.mjs',['installSessionFilesystem'],["import fs from 'node:fs';","import path from 'node:path';","import {randomBytes} from 'node:crypto';","import {syncBuiltinESMExports} from 'node:module';","import {decodeSessionSnapshot,encodeSessionSnapshot} from './session_snapshot.mjs';"])
    watches=wrapped('virtual_watch.mjs',['installVirtualWatchers'],["import fs from 'node:fs';","import path from 'node:path';","import {EventEmitter} from 'node:events';","import {syncBuiltinESMExports} from 'node:module';"])
    scope=wrapped('browser_session_scope.mjs',['scopeBrowserSession'],[])
    directory=once((ROOT/'readonly_directory.mjs').read_text(),'export function installVirtualDirectories','function installVirtualDirectories')
    entry=once((ROOT/'original_main_entry.mjs').read_text(),'  // INSERT_ORIGINAL_MODULE_HOOKS',hooks)
    entry=once(entry,'  // INSERT_FIXED_ORIGINAL_NATIVE_MAPPING',native_overlay(apk).decode())
    return (prefix+"\nimport {randomBytes} from 'node:crypto';\nimport {EventEmitter} from 'node:events';\n"+transport+codec+filesystem+watches+scope+directory+entry).encode()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('apk',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();args.output.write_bytes(build(args.apk))
