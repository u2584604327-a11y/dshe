#!/usr/bin/env python3
"""P148 exact signed v138 three EngineManager ProcessBuilder sites, structural only."""
import argparse,collections,hashlib,pathlib,re,sys,zipfile
from loguru import logger
logger.disable("androguard")
from androguard.core.dex import DEX
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from p35_original_engine_spawn_contract import EXPECTED,CODE_OFF,PC,inspect
ENGINE="Lcom/dsh/android/EngineManager;"
MAIN="Lcom/dsh/android/EngineManager$start$2;"
PB="Ljava/lang/ProcessBuilder;"
PAT=re.compile(r"(L[^\s,;]+;)->([^\s(,]+)\(([^)]*)\)")
def must(ok,why):
    if not ok:raise ValueError("P148_BLOCKED_"+why)
def source_gate(t):
    must(t.count("val pb = ProcessBuilder(")==3,"UPSTREAM_BUILDERS")
    must(t.count("val proc = pb.start()")==2,"UPSTREAM_HELPERS")
    must(t.count("            pb.start()")==1,"UPSTREAM_MAIN")
    names=("private fun probeBoot(","private fun runDumpConfig(","    suspend fun start()")
    must(all(t.count(n)==1 for n in names),"UPSTREAM_METHODS")
    a=t[t.index(names[0]):t.index(names[0])+12000]
    b=t[t.index(names[1]):t.index(names[1])+7000]
    c=t[t.index(names[2]):t.index(names[2])+48000]
    must("ProcessBuilder(cmd)" in a and "val proc = pb.start()" in a,"PROBE")
    must('"--dump-config"' in b and "val proc = pb.start()" in b,"CONFIG")
    must("ProcessBuilder(cmd)" in c and "process = proc" in c
         and "val urlPattern = URL_PATTERN" in c,"MAIN_READY")
def inspect_calls(m):
    out=[]
    ops=list(m.get_instructions_idx())
    must(len(ops)<40000,"METHOD_BOUNDS")
    for pc,i in ops:
        if not i.get_name().startswith("invoke-"):continue
        v=PAT.search(i.get_output())
        if v:out.append((pc,i.get_name(),v.group(1),v.group(2),v.group(3)))
    return out
def classify(calls):
    starts=[];ctors=[];ct=collections.Counter()
    for pc,op,owner,name,args in calls:
        if owner!=PB:continue
        if name=="start" and args=="":starts.append((pc,op))
        if name=="<init>":ctors.append((pc,args))
        if name in ("directory","environment","redirectErrorStream"):
            ct[name]+=1
    return starts,ctors,ct
def audit(apk,src):
    must(hashlib.sha256(apk.read_bytes()).hexdigest()==EXPECTED,"APK_SHA")
    must(inspect(apk)["primary_start_pc"]==PC,"P35_MAIN")
    source_gate(src.read_text(encoding="utf8"))
    with zipfile.ZipFile(apk) as z:d=DEX(z.read("classes.dex"))
    wanted={"PROBE":[],"CONFIG":[],"MAIN":[]};all_engine=[]
    for c in d.get_classes():
        n=c.get_name()
        if n not in (ENGINE,MAIN):continue
        for m in c.get_methods():
            if m.get_code() is None:continue
            all_engine.append(m)
            if n==ENGINE and m.get_name()=="probeBoot":wanted["PROBE"].append(m)
            if n==ENGINE and m.get_name()=="runDumpConfig":wanted["CONFIG"].append(m)
            if n==MAIN and m.get_name()=="invokeSuspend":wanted["MAIN"].append(m)
    must(all(len(x)==1 for x in wanted.values()),"THREE_REAL_METHODS")
    must(sum(len(classify(inspect_calls(m))[0]) for m in all_engine)==3,
         "THREE_REAL_START_CALLS")
    result={}
    for kind,matches in wanted.items():
        m=matches[0];starts,ctors,ct=classify(inspect_calls(m))
        must(len(starts)==1 and starts[0][1].startswith("invoke-virtual"),
             "ORIGINAL_START_"+kind)
        must(len(ctors)>=1,"BUILDER_NOT_IN_SAME_METHOD_"+kind)
        if kind=="MAIN":
            must(m.get_code_off()==CODE_OFF and starts[0][0]==PC,"MAIN_PC")
        result[kind]=(len(ctors),ct["directory"],ct["environment"],ct["redirectErrorStream"])
    return result
def synthetic():
    src=("val pb = ProcessBuilder("*3+
         "private fun probeBoot( ProcessBuilder(cmd) val proc = pb.start() "+
         "private fun runDumpConfig( \"--dump-config\" val proc = pb.start() "+
         "    suspend fun start() ProcessBuilder(cmd) process = proc "+
         "val urlPattern = URL_PATTERN            pb.start()")
    source_gate(src)
    try:source_gate(src.replace("val pb = ProcessBuilder(","",1))
    except ValueError as e:must("UPSTREAM_BUILDERS" in str(e),"SYNTH_NEGATIVE")
    else:raise AssertionError("P148_SOURCE_FAILOPEN")
    c=[(2,"invoke-virtual",PB,"<init>","Ljava/util/List;"),
       (4,"invoke-virtual",PB,"start","")]
    must(len(classify(c)[0])==1 and len(classify(c)[1])==1,"SYNTH_POSITIVE")
    must(len(classify(c+c[1:])[0])==2 and not classify(c[1:])[1],
         "SYNTH_DUPLICATE_MISSING")
    print("P148_SYNTHETIC_THREE_PATH_NEGATIVES=PASS")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--apk",type=pathlib.Path)
    p.add_argument("--upstream",type=pathlib.Path)
    p.add_argument("--synthetic",action="store_true")
    a=p.parse_args()
    if a.synthetic:synthetic();return
    must(a.apk is not None and a.upstream is not None,"INPUTS")
    d=audit(a.apk,a.upstream)
    print("P148_SIGNED_V138_THREE_REAL_DEX_SPAWNS=PASS")
    for k,v in d.items():print("P148_"+k+"_CATEGORICAL_COUNTS="+",".join(map(str,v)))
    print("P148_ARGV_CWD_ENV_VALUES_AND_ORIGINS=NOT_PROVEN")
    print("P148_UPSTREAM_BINARY_EQUIVALENCE=NOT_PROVEN")
    print("P148_P37_NODE_AND_HTTP_TOKEN_READY=NOT_WIRED")
    print("P148_ORIGINAL_SOURCE_SECRETS_PATHS_NOT_PRINTED=YES")
    print("P148_V139_RELEASE=BLOCKED")
if __name__=="__main__":main()
