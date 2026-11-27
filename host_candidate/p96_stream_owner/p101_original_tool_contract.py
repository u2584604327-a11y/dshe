#!/usr/bin/env python3
"""P101 exact-original model/tool/AgentLoop source-contract inventory.
Only pinned original APK; safe identifiers/counts, never source or user data.
No model, tool, session, network, Android or file writes.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

PACKAGES={'llm':'@deepseek-ai/dsh-llm','agentLoop':'@deepseek-ai/dsh-agent-loop','tools':'@deepseek-ai/dsh-tools'}
TOKENS=('prepareCall','stream','toolCall','toolResult','tools/result','tools.execute','notifyResult','callId','permission','approve','tool_result','tool_calls','register')
IDENT=rb'[A-Za-z_$][A-Za-z0-9_$]{0,64}'

def read_modules(apk):
    require(apk.stat().st_size==SOURCE_BYTES,'APK_SIZE_DRIFT')
    require(file_hash(apk)==SOURCE_SHA,'APK_SHA_DRIFT')
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None,'APK_CRC')
        engine=z.read('assets/engine.bin')
    modules={k:[] for k in PACKAGES}
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode='r|') as t:
        for n,item in enumerate(t,1):
            require(n<=50000,'TAR_LIMIT')
            if not item.isfile() or not item.name.endswith(('.js','.mjs','.cjs')):continue
            key=next((k for k,p in PACKAGES.items() if item.name.startswith('node_modules/'+p+'/')),None)
            if key is None:continue
            require(0<=item.size<=3000000,'MEMBER_SIZE')
            f=t.extractfile(item);require(f is not None,'MEMBER_MISSING')
            raw=f.read(3000001);require(len(raw)==item.size,'MEMBER_TRUNCATED')
            modules[key].append((item.name.split('/')[-1],raw))
    for k,v in modules.items():require(bool(v),'MISSING_'+k)
    return modules

def safe_context(raw,pos):
    window=raw[max(0,pos-300):min(len(raw),pos+300)]
    calls=re.findall(rb'('+IDENT+rb'(?:\.'+IDENT+rb'){1,3})\s*\(',window)
    props=re.findall(rb'('+IDENT+rb'(?:\??\.'+IDENT+rb'){1,3})',window)
    def safe(items):return sorted(set(x.decode('ascii').replace('?.','.') for x in items))[:20]
    return {'memberCalls':safe(calls),'propertyPaths':safe(props)}

def inspect(modules):
    result={}
    for kind,entries in modules.items():
        inventory=[]
        for basename,raw in entries:
            counts={t:raw.count(t.encode('ascii')) for t in TOKENS}
            if not any(counts.values()):continue
            sites=[]
            for token in TOKENS:
                for m in list(re.finditer(re.escape(token.encode('ascii')),raw))[:3]:
                    sites.append({'token':token,'line':raw.count(b'\n',0,m.start())+1,**safe_context(raw,m.start())})
            inventory.append({'file':basename if re.fullmatch(r'[A-Za-z0-9_.-]{1,90}',basename) else 'UNKNOWN',
                              'sha12':sha(raw)[:12],'counts':{k:v for k,v in counts.items() if v},
                              'sites':sites[:28]})
        result[kind]=inventory[:6]
    require(any('prepareCall' in x['counts'] for x in result['llm']),'PREPARE_CALL_MISSING')
    require(any('toolCall' in x['counts'] for x in result['agentLoop']),'AGENT_TOOL_CALL_MISSING')
    require(any('tools/result' in x['counts'] for x in result['tools']),'TOOL_RESULT_MISSING')
    print('P101_ORIGINAL_TOOL_CONTRACT='+json.dumps(result,sort_keys=True,separators=(',',':')))
    print('P101_ORIGINAL_MODULES_SOURCE_EXPORTED=NO')
    print('P101_ORIGINAL_MODEL_TOOL_AGENT_CONTRACT_SCAN=PASS')
    print('P101_ORIGINAL_AUTOMATIC_TOOL_CONTINUATION=NOT_TESTED')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--original',required=True)
    inspect(read_modules(pathlib.Path(parser.parse_args().original)))
