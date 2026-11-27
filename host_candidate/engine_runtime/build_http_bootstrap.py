#!/usr/bin/env python3
"""Build a sealed-resource original HTTP-services bootstrap, not the full profile.
Reuse the reviewed original module receiver/resolver, change only its explicit
wire version/EOF contract, and compose the reviewed HTTP/session adapters.
No network fetch, source rewriting inside the original module tree or arbitrary
entry path is accepted. The existing config bootstrap is left byte-identical.
"""
import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORE = ROOT.parent / 'p50_original_arm64_node/original_modules.mjs'
CORE_SHA = 'bc0c4c874e617016de0bd909c7c665795a7d6ff728e8245677f4e71074bbf140'


def once(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError('HTTP_BOOTSTRAP_SOURCE_ANCHOR')
    return source.replace(old, new)


def _compose(with_directory_adapter):
    raw = CORE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != CORE_SHA:
        raise RuntimeError('HTTP_BOOTSTRAP_REVIEWED_RESOURCE_CORE_SHA')
    original = raw.decode()
    prefix, run = original.split('async function run() {\n')
    setup, _ = run.split("  const mode = process.env.DSH_ORIGINAL_CONFIG_MODE", 1)
    # The full original tree seal remains required before any module import.
    # The continuation has its own version; legacy EOF config input cannot
    # silently turn into a long-lived control channel.
    prefix = once(prefix, "!== 'DSHMOD01'", "!== 'DSHMOD02'")
    prefix = once(prefix, '  const trailing = Buffer.alloc(1);\n', '')
    prefix = once(prefix, 'if (streamRead(trailing, 0, 1) !== 0 || members', 'if (members')
    transport = once((ROOT / 'http_transport.mjs').read_text(),
                     'export async function installHttpTransport', 'async function installHttpTransport')
    scope = once((ROOT / 'browser_session_scope.mjs').read_text(),
                 'export function scopeBrowserSession', 'function scopeBrowserSession')
    directory = once((ROOT / 'readonly_directory.mjs').read_text(),
                     'export function installVirtualDirectories', 'function installVirtualDirectories') if with_directory_adapter else ''
    entry = (ROOT / 'original_http_entry.mjs').read_text()
    marker = '// INSERT_REVIEWED_RESOURCE_INITIALIZATION\n'
    entry = once(entry, marker, setup + ('  installVirtualDirectories();\n' if with_directory_adapter else ''))
    return ('// Generated from pinned resource core and reviewed transport adapters.\n'
            '// Fixed original HTTP service composition; NOT the full main profile.\n' +
            prefix + '\n' + transport + '\n' + scope + ('\n' + directory if with_directory_adapter else '') + '\n' + entry).encode()


def build():
    return _compose(True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    data = build()
    args.output.write_bytes(data)
    print('SEALED_ORIGINAL_HTTP_BOOTSTRAP_SHA256=' + hashlib.sha256(data).hexdigest() + ' bytes=' + str(len(data)))
