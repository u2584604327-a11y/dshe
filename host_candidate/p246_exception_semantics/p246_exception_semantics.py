#!/usr/bin/env python3
"""P246 read-only DEX catch-table semantic classifier; no APK writes."""
import argparse,re,sys,zipfile
from pathlib import Path
class Deny(Exception):pass
def need(ok,code):
    if not ok:raise Deny("P246_DENY_"+code)
def decode(method,dex):
    code=method.get_code()
    need(code is not None,"CODE_REQUIRED")
    total=code.get_insns_size()
    need(type(total) is int and 0<total<=1000000,"CODE_UNITS")
    # Androguard instruction indices and lengths are BYTES, whereas
    # DEX code_item.insns_size and exception targets use 16-bit code units.
    # Require a gap-free full decode, not merely distinct aligned offsets.
    rows=list(method.get_instructions_idx())
    need(0<len(rows)<=1000000,"INST_COUNT")
    cursor=0
    valid=set()
    for pc,inst in rows:
        need(type(pc) is int and pc==cursor and pc%2==0,"INST_BOUNDARY")
        width=inst.get_length()
        need(type(width) is int and 0<width<=65536 and width%2==0,
             "INST_WIDTH")
        valid.add(pc//2)
        cursor+=width
        need(cursor<=2*total,"INST_RANGE")
    need(cursor==2*total,"INST_COVERAGE")
    tries=list(code.get_tries() or [])
    need(len(tries)==code.get_tries_size() and len(tries)<=512,"TRY_COUNT")
    table=code.get_handlers()
    if not tries:
        need(table is None or table.get_size()==0,"EMPTY_HANDLER_TABLE")
        return (total,())
    need(table is not None and 0<table.get_size()<=512,"HANDLER_TABLE")
    entries=list(table.get_list())
    need(len(entries)==table.get_size(),"HANDLER_ENTRY_COUNT")
    base=table.get_off()
    need(type(base) is int and base>=0,"HANDLER_LIST_OFFSET")
    handlers={}
    for h in entries:
        off=h.get_off()-base
        need(type(off) is int and off>0 and off not in handlers,"HANDLER_OFFSET")
        size=h.get_size()
        pairs=list(h.get_handlers() or [])
        need(type(size) is int and len(pairs)==abs(size),"HANDLER_SIZE")
        typed=[]
        for p in pairs:
            index=p.get_type_idx()
            need(type(index) is int and index>=0,"TYPE_INDEX")
            desc=dex.get_cm_type(index)
            need(type(desc) is str and re.fullmatch(r"L[^; \t\n]+;",desc),"TYPE_DESCRIPTOR")
            target=p.get_addr()
            need(type(target) is int and target in valid,"TYPED_TARGET")
            typed.append((desc,target))
        catchall=h.get_catch_all_addr() if size<=0 else None
        if size<=0:need(type(catchall) is int and catchall in valid,"CATCHALL_TARGET")
        need(bool(typed) or catchall is not None,"EMPTY_HANDLER")
        handlers[off]=(tuple(typed),catchall)
    out=[];last_end=-1
    referenced=set()
    for t in tries:
        start=t.get_start_addr();width=t.get_insn_count();off=t.get_handler_off()
        need(type(start) is int and type(width) is int and
             0<=start<total and width>0 and start in valid and
             (start+width in valid or start+width==total),"TRY_SPAN")
        need(start>=last_end,"TRY_OVERLAP_OR_ORDER")
        last_end=start+width
        need(type(off) is int and off in handlers,"TRY_BINDING")
        referenced.add(off)
        out.append((start,width,handlers[off]))
    # Never silently ignore an encoded_catch_handler that no try_item binds.
    # Even if it cannot be reached, unaccounted table data precludes a
    # full original-vs-derived *table* attestation.
    need(referenced==set(handlers),"UNREFERENCED_HANDLER")
    return (total,tuple(out))
def first_difference(left,right):
    need(type(left) is tuple and type(right) is tuple and
         len(left)==len(right)==2,"INPUT_SHAPE")
    if left[0]!=right[0]:return "CODE_SIZE"
    a,b=left[1],right[1]
    if len(a)!=len(b):return "TRY_COUNT"
    if a==b:return "SAME"
    if sorted(a,key=lambda x:(x[0],x[1]))==sorted(b,key=lambda x:(x[0],x[1])):
        return "TRY_ORDER"
    for x,y in zip(a,b):
        if x[:2]!=y[:2]:return "TRY_SPAN"
        ta,ca=x[2];tb,cb=y[2]
        if len(ta)!=len(tb):return "TYPED_COUNT"
        if ta!=tb and sorted(ta)==sorted(tb):return "HANDLER_ORDER"
        for (da,ra),(db,rb) in zip(ta,tb):
            if da!=db:return "TYPE_DESCRIPTOR"
            if ra!=rb:return "TYPED_TARGET"
        if (ca is None)!=(cb is None):return "CATCHALL_PRESENCE"
        if ca!=cb:return "CATCHALL_TARGET"
    return "UNCLASSIFIED_DENY"
def load(apk):
    from androguard.core.dex import DEX
    need(apk.is_file() and not apk.is_symlink(),"APK_FILE")
    with zipfile.ZipFile(apk) as z:
        need(z.testzip() is None and "classes.dex" in z.namelist(),"APK_ZIP_CRC")
        return DEX(z.read("classes.dex"))
def index(dex):
    output={}
    for cls in dex.get_classes():
        for m in cls.get_methods():
            k=(cls.get_name(),m.get_name(),"".join(m.get_descriptor().split()))
            need(k not in output,"DUPLICATE_METHOD")
            output[k]=m
    return output
def audit(base,candidate):
    da,db=load(base),load(candidate)
    aa,bb=index(da),index(db)
    helper=("Lcom/dsh/android/EngineManager$start$2;","p245Observe$ci",
            "(Lcom/dsh/android/EngineManager$start$2;)V")
    added=set(bb)-set(aa)
    need(added in (set(),{helper}) and set(aa)==set(bb)-added,"METHOD_SET")
    examined=0
    for key in sorted(aa):
        ma,mb=aa[key],bb[key]
        need((ma.get_code() is None)==(mb.get_code() is None),"METHOD_CODE")
        if ma.get_code() is None:continue
        examined+=1
        verdict=first_difference(decode(ma,da),decode(mb,db))
        if verdict!="SAME":
            group=("START_COROUTINE" if key[0]=="Lcom/dsh/android/EngineManager$start$2;"
                   and key[1]=="invokeSuspend" else "OTHER_PRIMARY")
            print("P246_FIRST_DIFF_GROUP="+group)
            print("P246_FIRST_DIFF_CATEGORY="+verdict)
            print("P246_EXCEPTION_PARITY=DENY")
            print("P246_RUNTIME_PROCESS_STATE=NOT_ATTESTED")
            return 2
    print("P246_METHOD_COUNT="+str(examined))
    print("P246_EXCEPTION_PARITY=PASS")
    print("P246_RUNTIME_PROCESS_STATE=NOT_ATTESTED")
    return 0
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--base",type=Path)
    p.add_argument("--candidate",type=Path)
    x=p.parse_args()
    if x.base is None and x.candidate is None:
        print("P246_CANDIDATE_BYTES=NOT_RETAINED")
        print("P246_REAL_EXCEPTION_DIFF=NOT_ATTESTED")
        print("P246_NO_APK_ASSEMBLY_OR_RUNTIME=PASS")
        return 0
    try:
        need(x.base is not None and x.candidate is not None,"BOTH_APKS_REQUIRED")
        return audit(x.base,x.candidate)
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P246_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
