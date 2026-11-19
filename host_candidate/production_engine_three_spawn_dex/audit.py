#!/usr/bin/env python3
"""Read-only exact signed-v138 EngineManager DEX three-spawn audit."""
import argparse
import hashlib
import json
import pathlib
import re
import zipfile

APK_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
MANAGER="Lcom/dsh/android/EngineManager;"
COROUTINE="Lcom/dsh/android/EngineManager$start$2;"
INVOKE=re.compile(r"(L[^;\s,]+;)->([^\s(,]+)\(([^)]*)\)")
MAX_DEX=64*1024*1024

class GateError(ValueError): pass
def require(test,reason):
    if not test: raise GateError("V138_TRIPLE_ENGINE_"+reason)

def mode(owner,name,params):
    if owner==COROUTINE and name=="invokeSuspend" and params=="Ljava/lang/Object;":
        return "primary"
    if owner==MANAGER and name=="probeBoot":return "probe"
    if owner==MANAGER and name=="runDumpConfig":return "config"
    return None

def verify(sites):
    require(len(sites)==3,"EXACT_THREE_SPAWNS_REQUIRED")
    require(sorted(s["mode"] for s in sites)==["config","primary","probe"],
            "DISTINCT_PROBE_CONFIG_PRIMARY_REQUIRED")
    main=next(s for s in sites if s["mode"]=="primary")
    require(main["dex"]=="classes.dex" and main["offset"]==3163260
            and main["pc"]==3912,"PINNED_MAIN_START_DRIFT")
    return sorted(sites,key=lambda s:("probe","config","primary").index(s["mode"]))

def selftest():
    good=[{"mode":"probe","dex":"classes.dex","offset":10,"pc":12},
          {"mode":"config","dex":"classes.dex","offset":20,"pc":24},
          {"mode":"primary","dex":"classes.dex","offset":3163260,"pc":3912}]
    require(mode(MANAGER,"probeBoot","")=="probe","PROBE_CLASSIFIER")
    require(mode(MANAGER,"runDumpConfig","")=="config","CONFIG_CLASSIFIER")
    require(mode(COROUTINE,"invokeSuspend","Ljava/lang/Object;")=="primary","MAIN_CLASSIFIER")
    require(mode(MANAGER,"start","") is None,"NO_FALSE_MAIN_CLASSIFIER")
    verify(good)
    negatives=[good[:2],good+[dict(good[2])],
               [good[0],good[0],good[2]],
               [good[0],good[1],dict(good[2],pc=3900)],
               [good[0],good[1],dict(good[2],offset=0)]]
    for bad in negatives:
        try: verify(bad)
        except GateError: continue
        raise AssertionError("V138_TRIPLE_ENGINE_FAIL_OPEN")
    print("V138_TRIPLE_ENGINE_NEGATIVE_POSITIVE_SELFTEST=PASS")

def audit(apk):
    require(apk.is_file(),"APK_MISSING")
    digest=hashlib.sha256()
    with apk.open("rb") as stream:
        for data in iter(lambda:stream.read(1048576),b""):digest.update(data)
    require(digest.hexdigest()==APK_SHA,"APK_SHA_DRIFT")
    from loguru import logger
    logger.disable("androguard")
    from androguard.core.dex import DEX
    sites=[]
    with zipfile.ZipFile(apk) as archive:
        infos=[info for info in archive.infolist()
               if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",info.filename)]
        require(1<=len(infos)<=8 and len(set(i.filename for i in infos))==len(infos),
                "DEX_ENTRY_DRIFT")
        for info in infos:
            require(0<info.file_size<=MAX_DEX,"DEX_UNBOUNDED")
            dex=DEX(archive.read(info))
            for cls in dex.get_classes():
                owner=cls.get_name()
                if owner!=MANAGER and not owner.startswith("Lcom/dsh/android/EngineManager$"):
                    continue
                for m in cls.get_methods():
                    if m.get_code() is None:continue
                    descriptor=m.get_descriptor()
                    params=descriptor[1:descriptor.index(")")]
                    for pc,insn in m.get_instructions_idx():
                        if not insn.get_name().startswith("invoke-"):continue
                        inv=INVOKE.search(insn.get_output())
                        if inv is None or inv.group(0)!="Ljava/lang/ProcessBuilder;->start()":
                            continue
                        require(len(sites)<32,"SPAWN_COUNT_UNBOUNDED")
                        classified=mode(owner,m.get_name(),params)
                        require(classified is not None,"UNCLASSIFIED_ENGINE_START")
                        require(insn.get_name()=="invoke-virtual","SPAWN_OPCODE_DRIFT")
                        sites.append({"mode":classified,"dex":info.filename,
                                      "offset":m.get_code_off(),"pc":pc})
    ordered=verify(sites)
    return {"signed_apk_sha":APK_SHA,"sites":ordered,
            "scope":"STATIC_EXACT_SIGNED_V138_DEX_CALLS_ONLY",
            "original_process_or_binder_wired":False,
            "original_node_ready":False,"formal_v139_apk":"BLOCKED"}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--selftest",action="store_true")
    p.add_argument("--original",type=pathlib.Path)
    p.add_argument("--report",type=pathlib.Path)
    args=p.parse_args()
    if args.selftest:return selftest()
    require(args.original is not None and args.report is not None,"INPUT_REQUIRED")
    report=audit(args.original)
    args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf8")
    print("V138_TRIPLE_ENGINE_APK_SHA=PASS")
    print("V138_TRIPLE_ENGINE_EXACT_THREE_DEX_SPAWNS=PASS_STATIC")
    print("V138_TRIPLE_ENGINE_ISOLATED_PRODUCTION_BROKER=NOT_WIRED")
    print("V138_TRIPLE_ENGINE_FORMAL_V139=BLOCKED")

if __name__=="__main__":main()
