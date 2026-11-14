#!/usr/bin/env python3
"""Read-only SHA-locked v138 APK DEX host class/method metadata inventory.
No code extraction, execution, decompilation, patching, signing or artifacts.
"""
import argparse
import hashlib
import json
import pathlib
import re
import struct
import zipfile

APK_SHA256='3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5'
APK_SIZE=147341486
MAX_DEX=20*1024*1024
MAX_CLASSES=100000
MAX_METHODS=250000
MAX_STRINGS=300000
CLASS_PATTERN=re.compile(
    r'^Lcom/dsh/android/(?:[^;]{0,128}/)?(?:MainActivity|DshApplication|'
    r'EngineManager|OverlayService|[^/;]*(?:Node|Binder|Isolated|Service|Runtime|Engine)[^/;]*);$')
REQUIRED_MAIN=re.compile(r'/MainActivity;$')

def check(ok,code):
    if not ok: raise ValueError('P102_BINARY_SOURCE_BLOCKED_'+code)

def u32(blob,at):
    check(0<=at<=len(blob)-4,'DEX_U32_BOUNDS')
    return struct.unpack_from('<I',blob,at)[0]

def u16(blob,at):
    check(0<=at<=len(blob)-2,'DEX_U16_BOUNDS')
    return struct.unpack_from('<H',blob,at)[0]

def uleb(blob,at):
    value=0
    for shift in (0,7,14,21,28):
        check(at<len(blob),'DEX_ULEB_BOUNDS')
        byte=blob[at]
        at+=1
        value|=(byte&0x7f)<<shift
        if byte<0x80:return value,at
    raise ValueError('P102_BINARY_SOURCE_BLOCKED_DEX_ULEB_OVERFLOW')

def table(blob,size_at,offset_at,width,maximum):
    count,offset=u32(blob,size_at),u32(blob,offset_at)
    check(count<=maximum,'DEX_TABLE_LIMIT')
    check((count==0 and offset==0) or (offset>=112 and
          offset+count*width<=len(blob)),'DEX_TABLE_BOUNDS')
    return count,offset

def scan_dex(blob):
    check(112<=len(blob)<=MAX_DEX,'DEX_SIZE')
    check(blob[:4]==b'dex\n' and blob[7]==0 and
          blob[4:7] in (b'035',b'037',b'038',b'039',b'040'),
          'DEX_MAGIC')
    check(u32(blob,32)==len(blob) and u32(blob,36)==112 and
          u32(blob,40)==0x12345678,'DEX_HEADER')
    string_count,string_off=table(blob,56,60,4,MAX_STRINGS)
    type_count,type_off=table(blob,64,68,4,MAX_STRINGS)
    method_count,method_off=table(blob,88,92,8,MAX_METHODS)
    class_count,class_off=table(blob,96,100,32,MAX_CLASSES)
    # DEX strings include long literal contents unrelated to class/method metadata.
    # Decode ONLY referenced type and method-name indices, with bounded symbols.
    string_cache={}
    def symbol(index):
        check(index<string_count,'DEX_STRING_INDEX')
        if index not in string_cache:
            pos=u32(blob,string_off+index*4)
            _,pos=uleb(blob,pos)
            end=blob.find(b'\0',pos,min(pos+4096,len(blob)))
            string_cache[index]=('<OVERLONG_DEX_SYMBOL>' if end<0 else
                                 blob[pos:end].decode('utf-8',errors='replace'))
        return string_cache[index]
    types=[]
    for i in range(type_count):
        index=u32(blob,type_off+i*4)
        check(index<string_count,'DEX_TYPE_INDEX')
        types.append(symbol(index))
    methods=[]
    for i in range(method_count):
        at=method_off+i*8
        owner,name_index=u16(blob,at),u32(blob,at+4)
        check(owner<type_count and name_index<string_count,'DEX_METHOD_INDEX')
        methods.append((types[owner],symbol(name_index)))
    targets=[]
    for i in range(class_count):
        at=class_off+i*32
        type_index,data_off=u32(blob,at),u32(blob,at+24)
        check(type_index<type_count,'DEX_CLASS_INDEX')
        descriptor=types[type_index]
        if not CLASS_PATTERN.fullmatch(descriptor):continue
        names=[]
        if data_off:
            counts=[]
            cursor=data_off
            for _ in range(4):
                n,cursor=uleb(blob,cursor)
                check(n<=MAX_METHODS,'DEX_CLASS_DATA_LIMIT')
                counts.append(n)
            for _ in range(counts[0]+counts[1]):
                _,cursor=uleb(blob,cursor)
                _,cursor=uleb(blob,cursor)
            for length in counts[2:]:
                index=0
                for _ in range(length):
                    delta,cursor=uleb(blob,cursor)
                    index+=delta
                    _,cursor=uleb(blob,cursor)
                    code_off,cursor=uleb(blob,cursor)
                    check(index<method_count,'DEX_CLASS_METHOD_INDEX')
                    check(methods[index][0]==descriptor,'DEX_CLASS_METHOD_OWNER')
                    name=methods[index][1]
                    if (len(names)<80 and name not in ('<init>','<clinit>') and
                        re.search(r'onCreate|onBind|onDestroy|start|stop|engine|'
                                  r'node|binder|service|attach|session|tool|'
                                  r'init|run|process|connect|webview',
                                  name,re.I)):
                        names.append({'name':name,'has_code':code_off!=0})
        targets.append({'class':descriptor,'methods':names})
    return {'class_count':class_count,'method_count':method_count,
            'target_classes':targets}

def audit(apk):
    check(apk.is_file() and apk.stat().st_size==APK_SIZE,'APK_SIZE')
    digest=hashlib.sha256()
    with apk.open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):digest.update(part)
    check(digest.hexdigest()==APK_SHA256,'APK_SHA256')
    with zipfile.ZipFile(apk) as z:
        dex_names=sorted(n for n in z.namelist()
                         if re.fullmatch(r'classes(?:[2-9][0-9]*)?\.dex',n))
        check(1<=len(dex_names)<=8 and len(set(dex_names))==len(dex_names),
              'APK_DEX_ENTRIES')
        results=[]
        for name in dex_names:
            info=z.getinfo(name)
            check(0<info.file_size<=MAX_DEX,'APK_DEX_LIMIT')
            dex=z.read(name)
            report=scan_dex(dex)
            report['dex_name']=name
            report['dex_sha256']=hashlib.sha256(dex).hexdigest()
            results.append(report)
    classes=[v for result in results for v in result['target_classes']]
    main=[v for v in classes if REQUIRED_MAIN.search(v['class'])]
    print('P102_EXACT_SIGNED_V138_APK_SOURCE_SHA=PASS')
    print('P102_DEX_HOST_METHOD_METADATA='+json.dumps(
        {'dex':results},sort_keys=True,separators=(',',':')))
    print('P102_MAIN_ACTIVITY_DEFINED='+('YES' if main else 'NO'))
    print('P102_ENGINE_MANAGER_OR_TOOL_BINDER_PRODUCTION_HOOK=NOT_PROVEN')
    print('P102_PRODUCTION_NODE_TOOLRUNTIME_ANDROID_BINDER=NOT_WIRED')
    check(main,'MAIN_ACTIVITY_NOT_MAPPED')

def selftest():
    assert uleb(bytes([0x80,0x01]),0)==(128,2)
    assert uleb(bytes([0x7f]),0)==(127,1)
    assert CLASS_PATTERN.fullmatch('Lcom/dsh/android/MainActivity;')
    assert CLASS_PATTERN.fullmatch('Lcom/dsh/android/engine/EngineManager;')
    assert not CLASS_PATTERN.fullmatch('Lcom/other/app/MainActivity;')
    try:u32(b'abc',0)
    except ValueError:pass
    else:raise AssertionError('bounds failure')
    print('P102_READONLY_DEX_METADATA_PARSER_SELFTEST=PASS')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--original',type=pathlib.Path)
    p.add_argument('--selftest',action='store_true')
    args=p.parse_args()
    if args.selftest:selftest()
    else:
        check(args.original is not None,'ORIGINAL_REQUIRED')
        audit(args.original)
