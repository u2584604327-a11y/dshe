#!/usr/bin/env python3
"""Compose a main-profile transport with synchronous owned-snapshot commits.
The approved component transport and its historical failure bytes stay intact.
Only our reviewed transport implementation is composed, never original JS.
"""
import argparse
from pathlib import Path
from build_http_bootstrap import once
ROOT=Path(__file__).resolve().parent


def build():
    base=(ROOT/'http_transport.mjs').read_text()
    wire=(ROOT/'profile_wire.mjs').read_text().replace("import fs from 'node:fs';\n",'')
    wire=once(wire,'export class ProfileWire','class ProfileWire')
    base=once(base,'export async function installHttpTransport({input = process.stdin, output = process.stdout} = {}) {',
              'async function installProfileTransport({input = process.stdin, output = process.stdout, onFailure = () => {}} = {}) {')
    base=once(base,'  const source = new Source(input);','  const source = new ProfileWire(input,output);')
    start=base.index('  function send(type, id, payload = empty) {')
    end=base.index('  const control = ',start)
    send='''  function sendProfileSync(type,id,payload=empty) {
    if(closed||payload.length>CHUNK||sending===0x7fffffffffffffffn)throw error('E_DSH_IPC_OUTPUT_BOUND');
    const header=Buffer.alloc(21);header.write('DHF1',0,'ascii');header[4]=type;header.writeBigUInt64BE(++sending,5);
    header.writeUInt32BE(id,13);header.writeUInt32BE(payload.length,17);
    source.writeFrame(Buffer.concat([header,tag('N',header,payload),payload]),profileDeadline);
  }
  function send(type,id,payload=empty) {
    try{sendProfileSync(type,id,payload);return Promise.resolve();}catch(cause){return Promise.reject(cause);}
  }
'''
    base=base[:start]+send+base[end:]
    start=base.index('  const reading = (async () => {')
    actions_start=base.index('      if (type === H.APP_DATA)',start)
    actions_end=base.index('\n    }\n  })().catch',actions_start)
    actions=base[actions_start:actions_end].replace('continue;','return;')
    protocol=(ROOT/'profile_protocol.mjs').read_text()
    protocol=once(protocol,'  // INSERT_ORIGINAL_HTTP_FRAME_ACTIONS',
                  '  const {type,id,length,data}=frame;\n'+actions)
    end=base.index('\n  return {',actions_end)
    base=base[:start]+protocol+base[end:]
    base=once(base,'    port, requestedPort, reading,',
              '    port, requestedPort, reading, filesystem: Object.freeze({ready:storageReady.promise,commit:commitSnapshot}),')
    base=once(base,'    input.destroy();\n    // Fixed diagnostic',
              '    source.stop(cause);storageReady.reject(cause);try{onFailure();}catch{}\n    input.destroy();\n    queueMicrotask(()=>process.exit(125));\n    // Fixed diagnostic')
    base=once(base,'      closed = true; key.fill(0); input.destroy(); applicationInput.destroy();',
              '      closed = true; key.fill(0); source.stop(); input.destroy(); applicationInput.destroy();')
    base=once(base,'async function installProfileTransport(', 'export async function installProfileTransport(')
    return ("import fs from 'node:fs';\nimport {createHash} from 'node:crypto';\n"+wire+'\n'+base).encode()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args();args.output.write_bytes(build())
