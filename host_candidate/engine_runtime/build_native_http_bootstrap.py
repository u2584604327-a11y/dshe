#!/usr/bin/env python3
"""Compose original HTTP plus the fixed original native-binding prerequisite.
The complete original main profile/EngineManager remains unauthorized here.
"""
import argparse
import hashlib
from pathlib import Path
from build_http_bootstrap import build as http_bootstrap, once
from build_native_overlay import build as native_overlay


def build(apk):
    source = http_bootstrap().decode()
    overlay = native_overlay(apk).decode()
    overlay = once(overlay, '}, pageSize);', '}, 4096);')
    source = once(source, '  receiveModules();\n  installReadonlyFilesystem();',
                  '  receiveModules();\n' + overlay + '  installReadonlyFilesystem();')
    if source.count('format: formatOf(filename)') != 2:
        raise ValueError('ADDON_MAPPING_FORMAT_SEAM')
    source = source.replace('format: formatOf(filename)', 'format: nativeMapping.format(filename) ?? formatOf(filename)')
    source = once(source, '      const source = files.get(filename);',
                  '      const source = nativeMapping.source(filename) ?? files.get(filename);')
    probe = '''
  // Exercise the unchanged original public loader and all five internal APIs
  // required by original app-boot host preparation. No native API is mocked.
  const {createRequire} = await import('node:module');
  const addon = createRequire(pathToFileURL(ENTRY))('node-addon-require-builtin');
  const info = addon.getBindingInfo();
  if (info.product !== 'require-builtin' || info.backend !== 'napi' || info.abi !== 'napi-v9') fail('E_DSH_ADDON_BINDING_INFO');
  for (const id of ['internal/modules/esm/loader', 'internal/modules/cjs/loader',
                    'internal/modules/helpers', 'internal/modules/esm/utils', 'internal/modules/esm/resolve']) {
    if (!addon.isAllowedInternalId(id) || !addon.requireBuiltin(id)) fail('E_DSH_ADDON_INTERNAL_API');
  }
  const esm = addon.requireBuiltin('internal/modules/esm/loader').getOrInitializeCascadedLoader();
  const cjs = addon.requireBuiltin('internal/modules/cjs/loader');
  const helpers = addon.requireBuiltin('internal/modules/helpers');
  const utils = addon.requireBuiltin('internal/modules/esm/utils');
  const resolve = addon.requireBuiltin('internal/modules/esm/resolve');
  const modern = typeof esm.getOrCreateModuleJob === 'function';
  if (typeof esm.resolveSync !== 'function' ||
      (!modern && (typeof esm.getModuleJobForImport !== 'function' || typeof esm.resolve !== 'function')) ||
      typeof cjs.Module?._resolveFilename !== 'function' || typeof helpers.getCjsConditions !== 'function' ||
      typeof utils.getDefaultConditions !== 'function' || typeof resolve.defaultResolve !== 'function') fail('E_DSH_ADDON_LOADER_API_SHAPE');
  if (addon.isAllowedInternalId('internal/child_process')) fail('E_DSH_ADDON_INTERNAL_ID_ESCAPE');
  try { addon.requireBuiltin('internal/child_process'); fail('E_DSH_ADDON_INTERNAL_ID_ESCAPE'); }
  catch (error) { if (error.code !== 'E_DSH_ADDON_INTERNAL_ID_DENIED') throw error; }
'''
    source = once(source, '  const transport = await installHttpTransport();originalServiceTransport=transport;\n',
                  '  const transport = await installHttpTransport();originalServiceTransport=transport;\n' + probe)
    source = once(source, "  process.stdout.write('DSH_ORIGINAL_HTTP_RESOURCE_MODULES=' + loaded.size + '\\n');",
                  "  process.stdout.write('DSH_ORIGINAL_HTTP_RESOURCE_MODULES=' + loaded.size + '\\n');\n"
                  "  process.stdout.write('DSH_ORIGINAL_ANDROID_NATIVE_BINDING=PASS\\n');")
    return source.encode()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    data = build(args.apk)
    with args.output.open('xb') as output:
        output.write(data)
    print('ORIGINAL_NATIVE_HTTP_BOOTSTRAP_SHA256=' + hashlib.sha256(data).hexdigest() + ' bytes=' + str(len(data)))
