#!/usr/bin/env python3
"""P298: independent read-only DEX string/type/field pool reference census.

Compare actual raw indexed references in the 492 previously not-attested
original methods. Never use get_output() or Androguard operand display as a
pool witness. Ordinary 35c/3rc method refs belong to P297, not P298.
Switch/fill-array payload targets, register data flow, ART and isolation remain
NOT ATTESTED. All results categorically DENY release; no private values logged.
"""
import argparse,re,sys
from collections import Counter
from pathlib import Path
sys.path[:0]=[
 "host_candidate/p246_exception_semantics",
 "host_candidate/p249_dual_diff",
 "host_candidate/p251_method_relation",
 "host_candidate/p253_cfg_ordinal",
 "host_candidate/p255_branch_separation",
 "host_candidate/p257_opcode_family",
 "host_candidate/p259_all_operands",
 "host_candidate/p261_all_method_census",
 "host_candidate/p263_operand_correlation",
 "host_candidate/p265_operand_shape",
 "host_candidate/p267_invoke_words",
 "host_candidate/p269_method_pool",
 "host_candidate/p295_raw_unknowns",
 "host_candidate/p296_instruction_shape",
 "host_candidate/p297_raw_invoke_pool",
]
from p246_exception_semantics import load,need,index
from p249_dual_diff import seal
from p263_operand_correlation import diagnose
from p261_all_method_census import method_observation
from p295_raw_unknowns import instruction_bytes
from p296_instruction_shape import encoded_shape

# Maps each ordinary DEX instruction with a non-method pool index to
# (resolved pool kind, instruction total length in bytes, index byte width).
REF_SPEC={
 0x1a:("STRING",4,2),   # const-string (21c)
 0x1b:("STRING",6,4),   # const-string/jumbo (31c)
 0x1c:("TYPE",4,2),     # const-class (21c)
 0x1f:("TYPE",4,2),     # check-cast (21c)
 0x20:("TYPE",4,2),     # instance-of (22c)
 0x22:("TYPE",4,2),     # new-instance (21c)
 0x23:("TYPE",4,2),     # new-array (22c)
 0x24:("TYPE",6,2),     # filled-new-array (35c)
 0x25:("TYPE",6,2),     # filled-new-array/range (3rc)
}
for op in range(0x52,0x6e):  # iget/iput 22c + sget/sput 21c
    REF_SPEC[op]=("FIELD",4,2)
# Must not silently treat DEX 038 call sites, handles or reserved/odex
# opcodes as ordinary string/type/field references.
UNSUPPORTED=frozenset(range(0x3e,0x44))|frozenset((0x73,0x79,0x7a))|frozenset(range(0xe3,0x100))
INVOKE_METHOD=frozenset(range(0x6e,0x73))|frozenset(range(0x74,0x79))
CATEGORIES=(
 "MATCHING_OTHER_REFERENCE_TARGETS_CANDIDATE",
 "DIFFERENT_OTHER_REFERENCE_TARGET",
 "OTHER_REFERENCE_POOL_UNAVAILABLE",
 "UNSUPPORTED_REFERENCE_ENCODING",
 "NO_OTHER_POOL_REFERENCE_OBSERVED",
 "INSTRUCTION_LAYOUT_UNVERIFIED",
)
KIND=("STRING","TYPE","FIELD")
LIMIT=1000000

def valid_type(s):
    if not isinstance(s,str) or not (0<len(s)<=8192):
        return False
    # Primitive, object and non-void arrays. No descriptor-internal space.
    return re.fullmatch(r"(?:[ZBCSIFJD]|L[^;()\s]+;|\[+(?:[ZBCSIFJD]|L[^;()\s]+;))",s) is not None

def pool_value(dex,kind,idx):
    """Return ('ok', opaque comparable value) or None, never log the value."""
    try:
        if type(idx) is not int or idx<0 or idx>0xffffffff:
            return None
        if kind=="STRING":
            val=dex.get_cm_string(idx)
            if not isinstance(val,str) or len(val)>8192:return None
            return val
        if kind=="TYPE":
            val=dex.get_cm_type(idx)
            return val if valid_type(val) else None
        if kind=="FIELD":
            val=dex.get_cm_field(idx)
            if not isinstance(val,(tuple,list)) or len(val)!=3:return None
            owner,typ,name=val
            if (not isinstance(owner,str) or re.fullmatch(r"L[^;()\s]+;",owner) is None
                or not valid_type(typ) or not isinstance(name,str) or not (0<len(name)<=8192)
                or re.search(r"[()\s]",name)):
                return None
            return (owner,typ,name)
    except Exception:
        return None
    return None

def references(method,dex):
    """Full-gapless code-item coverage and raw index decoding only."""
    if instruction_bytes(method) is None:return None
    try:
        rows=list(method.get_instructions_idx())
        out=[]
        for ordinal,(_,inst) in enumerate(rows):
            data=inst.get_raw()
            if type(data) is not bytes or len(data)<2:return None
            op=data[0]
            if op in UNSUPPORTED:return "UNSUPPORTED"
            spec=REF_SPEC.get(op)
            if spec is None:continue
            kind,length,width=spec
            if len(data)!=length:return None
            idx=int.from_bytes(data[2:2+width],"little")
            resolved=pool_value(dex,kind,idx)
            if resolved is None:return None
            out.append((ordinal,op,kind,resolved))
        return tuple(out)
    except Exception:
        return None

def category(a,b,da,db):
    if encoded_shape(a,b) not in ("RAW_EXACT","RAW_DIFFER_SAME_SHAPE"):
        return "INSTRUCTION_LAYOUT_UNVERIFIED"
    ra,rb=references(a,da),references(b,db)
    if ra=="UNSUPPORTED" or rb=="UNSUPPORTED":
        return "UNSUPPORTED_REFERENCE_ENCODING"
    if ra is None or rb is None or type(ra) is not tuple or type(rb) is not tuple:
        return "OTHER_REFERENCE_POOL_UNAVAILABLE"
    if len(ra)!=len(rb):
        return "INSTRUCTION_LAYOUT_UNVERIFIED"
    if not ra:return "NO_OTHER_POOL_REFERENCE_OBSERVED"
    for x,y in zip(ra,rb):
        if x[:3]!=y[:3]:
            return "INSTRUCTION_LAYOUT_UNVERIFIED"
        if x[3]!=y[3]:
            return "DIFFERENT_OTHER_REFERENCE_TARGET"
    return "MATCHING_OTHER_REFERENCE_TARGETS_CANDIDATE"

def audit(original,candidate,da,db):
    previous=diagnose(original,candidate,da,db)
    n=previous["unknown"]
    out=Counter({c:0 for c in CATEGORIES})
    for key in sorted(original):
        a,b=original[key],candidate[key]
        if a.get_code() is None:continue
        if method_observation(a,b,da,db)["OPERANDS_NOT_ATTESTED"]:
            label=category(a,b,da,db)
            need(label in CATEGORIES,"P298_CATEGORY")
            out[label]+=1
    need(sum(out.values())==n,"P298_TOTAL_RECONCILE")
    return {"count":n,"categories":dict(out)}

def emit(q):
    need(type(q) is dict and set(q)=={"count","categories"},"P298_RESULT")
    n,c=q["count"],q["categories"]
    need(type(n) is int and 0<=n<=LIMIT,"P298_COUNT")
    need(type(c) is dict and set(c)==set(CATEGORIES),"P298_FIELDS")
    need(all(type(x) is int and 0<=x<=n for x in c.values())
         and sum(c.values())==n,"P298_TOTAL")
    print("P298_UNKNOWN_METHODS="+str(n))
    for key in CATEGORIES:print("P298_"+key+"="+str(c[key]))
    print("P298_ONLY_STRING_TYPE_FIELD_POOL_REFERENCES=YES")
    print("P298_ORDINARY_INVOKE_METHOD_POOL=SEPARATE_P297")
    print("P298_SWITCH_PAYLOAD_REGISTERS_ART=NOT_ATTESTED")
    print("P298_ORIGINAL_P245_GATE=UNMODIFIED")
    print("P298_ISOLATED_CHILD_P192_B3_B4=NOT_ATTESTED")
    print("P298_PRIVATE_REFERENCES_INDICES_AND_PCS=WITHHELD")
    print("P298_RELEASE=DENY")
    print("P298_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    ap=argparse.ArgumentParser()
    for n in ("signed-original","base","candidate"):ap.add_argument("--"+n,type=Path)
    args=ap.parse_args();ps=(args.signed_original,args.base,args.candidate)
    if all(x is None for x in ps):
        print("P298_SOURCE_ONLY=YES")
        print("P298_REAL_OTHER_POOL_REFS=NOT_ATTESTED")
        print("P298_RELEASE=DENY")
        print("P298_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in ps),"P298_PINNED_THREE_APKS")
        seal(args.signed_original)
        da,db=load(args.base),load(args.candidate)
        return emit(audit(index(da),index(db),da,db))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",code):
            code="P298_DENY_UNEXPECTED"
        print(code,file=sys.stderr)
        return 2
if __name__=="__main__":raise SystemExit(main())
