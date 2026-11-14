#!/usr/bin/env python3
"""P285 read-only strict DEX shadow verifier for the CI-only P245 helper.

Does NOT import, modify, replace, monkeypatch or waive P245's full gate.
Enforces raw 22c field and raw 35c method IDs, typed descriptor sequences,
exact register words/frame, full bounded instruction order/branch targets,
typed Throwable handler and unchanged original method-set/code-size/exception
table shape. Outputs only fixed categories, never private DEX identities/PCs.
Even an all-PASS shadow verdict is NOT ART or release authorization.
"""
import argparse
import re
import sys
from pathlib import Path
sys.path[:0]=[
 "host_candidate/p246_exception_semantics",
 "host_candidate/p249_dual_diff",
 "host_candidate/p267_invoke_words",
 "host_candidate/p269_method_pool",
 "host_candidate/p281_helper_predicates",
 "host_candidate/p283_descriptor_normalization",
]
from p246_exception_semantics import index,load,decode,need
from p249_dual_diff import seal,dual
from p267_invoke_words import raw_words
from p269_method_pool import method_pool
from p281_helper_predicates import helper_rows,OWNER,NAME,DESC,GETTER,LOG
from p283_descriptor_normalization import canonical_args,canonical_return

ENGINE="Lcom/dsh/android/EngineManager;"
KEY=(OWNER,NAME,DESC)
OPS=("iget-object","if-eqz","invoke-static","move-result-object",
     "if-eqz","const-string","const-string","goto",
     "const-string","const-string","invoke-static","return-void",
     "move-exception","return-void")
FACTORS=("METHOD_SET","BASE_CODE_SIZE","BASE_EXCEPTION",
         "FRAME","INSTRUCTION_SEQUENCE","BRANCH_TARGETS",
         "CAPTURED_FIELD","GETTER_RAW_35C","LOG_RAW_35C",
         "SAFE_LITERAL_FLOW","TYPED_TRY_CATCH")
STATUS=("PASS","FAIL","UNVERIFIED")
SHADOW=("STRICT_STRUCTURAL_CANDIDATE_ONLY","DENY")
TAG=("DSH","MainActivity","Android","Log")
LABELS=("true","false")

def fail_template():
    return {k:"UNVERIFIED" for k in FACTORS}

def capture_from_baseline(dex):
    """Only a single original captured EngineManager field can be trusted."""
    try:
        classes=[c for c in dex.get_classes() if c.get_name()==OWNER]
        if len(classes)!=1:return None
        fields=[]
        for f in classes[0].get_fields():
            if (f.get_descriptor()==ENGINE and
                f.get_class_name()==OWNER and isinstance(f.get_name(),str)):
                fields.append(f.get_name())
        if len(fields)!=1 or not re.fullmatch(r"[A-Za-z_$][A-Za-z_$0-9]*",fields[0]):
            return None
        return fields[0]
    except Exception:
        return None

def raw_field(row,dex,capture):
    """22c iget-object v0, p0 (=v4), ref must match ORIGINAL capture."""
    if capture is None:return "UNVERIFIED"
    if row[1]!="iget-object":return "FAIL"
    try:
        raw=row[3].get_raw()
        if (not isinstance(raw,(bytes,bytearray)) or len(raw)!=4):
            return "UNVERIFIED"
        if raw[0]!=0x54 or raw[1]!=0x40:return "FAIL"
        index_value=int.from_bytes(raw[2:4],"little")
        field=dex.get_cm_field(index_value)
        if not isinstance(field,(list,tuple)) or len(field)!=3:
            return "UNVERIFIED"
        if not all(isinstance(x,str) and len(x)<=8192 for x in field):
            return "UNVERIFIED"
        return "PASS" if tuple(field)==(OWNER,ENGINE,capture) else "FAIL"
    except Exception:
        return "UNVERIFIED"

def raw_static(row,dex,expected,registers):
    """Exact raw 35c method index, register words and canonical DEX tuple."""
    if row[1]!="invoke-static":return "FAIL"
    x=raw_words(row[:4])
    if x is None:return "UNVERIFIED"
    words,idx=x
    if words!=registers:return "FAIL"
    ref=method_pool(dex,idx)
    if ref is None:return "UNVERIFIED"
    owner,name,args,ret=ref
    ca=canonical_args(args);cr=canonical_return(ret)
    if ca is None or cr is None:return "UNVERIFIED"
    return "PASS" if (owner,name,ca,cr)==expected else "FAIL"

def shape(rows):
    """Exact 14-instruction CI helper, not an arbitrary code gadget."""
    if rows is None:return "UNVERIFIED"
    names=tuple(r[1] for r in rows)
    allowed=tuple((x,"const-string/jumbo") for x in OPS if x=="const-string")
    if len(names)!=14:return "FAIL"
    for name,expect in zip(names,OPS):
        if name!=expect and not (expect=="const-string" and
                                 name=="const-string/jumbo"):
            return "FAIL"
    return "PASS"

def branches(rows):
    if shape(rows)!="PASS":return "UNVERIFIED"
    positions=(1,4,7)
    targets=(rows[8][0],rows[8][0],rows[10][0])
    for i,expected in zip(positions,targets):
        row=rows[i]
        try:
            offset=row[3].get_ref_off()
        except Exception:return "UNVERIFIED"
        if type(offset) is not int:return "UNVERIFIED"
        if row[0]+offset!=expected:return "FAIL"
    return "PASS"

def frame(method):
    try:
        c=method.get_code()
        sizes=(c.get_registers_size(),c.get_ins_size(),c.get_outs_size())
        if not all(type(x) is int and 0<=x<=65535 for x in sizes):
            return "UNVERIFIED"
        return "PASS" if sizes==(5,1,2) else "FAIL"
    except Exception:return "UNVERIFIED"

def try_catch(method,dex,rows):
    """Exact protected entry through log, and post-try Throwable handler."""
    if shape(rows)!="PASS":return "UNVERIFIED"
    try:
        total,items=decode(method,dex)
        if len(items)!=1:return "FAIL"
        start,length,(typed,catchall)=items[0]
        if (start!=0 or start+length!=rows[11][0] or
            len(typed)!=1 or typed[0][0]!="Ljava/lang/Throwable;" or
            catchall is not None or typed[0][1]!=rows[12][0] or
            rows[-1][0]>=total):
            return "FAIL"
        return "PASS"
    except Exception:return "UNVERIFIED"

def literal_ref(row,dex,dest_register):
    if row[1] not in ("const-string","const-string/jumbo"):
        return None
    try:
        raw=row[3].get_raw()
        jumbo=row[1].endswith("/jumbo")
        if (not isinstance(raw,(bytes,bytearray)) or
            len(raw)!=(6 if jumbo else 4) or
            raw[0]!=(0x1b if jumbo else 0x1a) or
            raw[1]!=dest_register):
            return None
        idx=int.from_bytes(raw[2:],"little")
        val=dex.get_cm_string(idx)
        return val if isinstance(val,str) and len(val)<=8192 else None
    except Exception:return None

def safe_literal_flow(rows,dex):
    if shape(rows)!="PASS":return "UNVERIFIED"
    first=literal_ref(rows[5],dex,1)
    yes=literal_ref(rows[6],dex,2)
    other=literal_ref(rows[8],dex,1)
    no=literal_ref(rows[9],dex,2)
    if None in (first,yes,other,no):return "UNVERIFIED"
    return ("PASS" if first==other and first in TAG and
            (yes,no)==LABELS else "FAIL")

def inspect_helper(method,dex,capture):
    statuses={x:"UNVERIFIED" for x in FACTORS}
    rows=helper_rows(method)
    statuses["FRAME"]=frame(method)
    statuses["INSTRUCTION_SEQUENCE"]=shape(rows)
    if rows is None:return statuses
    statuses["BRANCH_TARGETS"]=branches(rows)
    if shape(rows)!="PASS":return statuses
    statuses["CAPTURED_FIELD"]=raw_field(rows[0],dex,capture)
    statuses["GETTER_RAW_35C"]=raw_static(rows[2],dex,GETTER,(0,))
    statuses["LOG_RAW_35C"]=raw_static(rows[10],dex,LOG,(1,2))
    statuses["SAFE_LITERAL_FLOW"]=safe_literal_flow(rows,dex)
    statuses["TYPED_TRY_CATCH"]=try_catch(method,dex,rows)
    return statuses

def audit(base_dex,candidate_dex):
    a,b=index(base_dex),index(candidate_dex)
    result=fail_template()
    if set(b)-set(a)!={KEY} or set(a)!=set(b)-{KEY}:
        result["METHOD_SET"]="FAIL"
        return result
    result["METHOD_SET"]="PASS"
    p=dual(a,b,base_dex,candidate_dex)
    result["BASE_CODE_SIZE"]="PASS" if p["code_gate"]=="PARITY" else "FAIL"
    result["BASE_EXCEPTION"]="PASS" if p["exception_gate"]=="PARITY" else "FAIL"
    result.update({k:v for k,v in inspect_helper(b[KEY],candidate_dex,
                                     capture_from_baseline(base_dex)).items()
                   if k not in ("METHOD_SET","BASE_CODE_SIZE","BASE_EXCEPTION")})
    return result

def emit(q):
    need(type(q) is dict and set(q)==set(FACTORS),"PUBLIC_SCHEMA")
    need(all(q[x] in STATUS for x in FACTORS),"STATUS_ENUM")
    if q["METHOD_SET"]!="PASS":
        need(all(q[x]=="UNVERIFIED" for x in FACTORS if x!="METHOD_SET"),
             "METHOD_SET_DEPENDENCY")
    for name in FACTORS:
        print("P285_"+name+"="+q[name])
    value=("STRICT_STRUCTURAL_CANDIDATE_ONLY"
           if all(v=="PASS" for v in q.values()) else "DENY")
    need(value in SHADOW,"VERDICT_ENUM")
    print("P285_SHADOW="+value)
    print("P285_ORIGINAL_P245_GATE=UNMODIFIED")
    print("P285_SHADOW_DOES_NOT_AUTHORIZE_ART_OR_RELEASE=YES")
    print("P285_PRIVATE_STRINGS_REGISTERS_INDICES_PCS=WITHHELD")
    print("P285_RELEASE=DENY")
    print("P285_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    p=argparse.ArgumentParser()
    for name in ("signed-original","base","candidate"):
        p.add_argument("--"+name,type=Path)
    x=p.parse_args()
    paths=(x.signed_original,x.base,x.candidate)
    if all(v is None for v in paths):
        print("P285_SOURCE_ONLY=YES")
        print("P285_REAL_SHADOW=NOT_ATTESTED")
        print("P285_RELEASE=DENY")
        print("P285_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(v is not None for v in paths),"THREE_PINNED_INPUTS")
        seal(x.signed_original)
        return emit(audit(load(x.base),load(x.candidate)))
    except Exception as e:
        code=str(e)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P285_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":
    raise SystemExit(main())
