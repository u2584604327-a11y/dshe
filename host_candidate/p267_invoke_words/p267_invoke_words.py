#!/usr/bin/env python3
"""P267: private original 35c vs 3rc invoke argument-word audit, fail closed.

This diagnostic does NOT assert instruction/ART equivalence, and MUST NOT be used
as a production gate. No method identity, registers, refs, PCs or operand values
may be printed. P245 and all process/isolation guards remain unchanged.
"""
import argparse,re,sys
from collections import Counter
from pathlib import Path
sys.path[:0]=["host_candidate/p246_exception_semantics",
             "host_candidate/p249_dual_diff",
             "host_candidate/p251_method_relation",
             "host_candidate/p253_cfg_ordinal",
             "host_candidate/p255_branch_separation",
             "host_candidate/p257_opcode_family",
             "host_candidate/p259_all_operands",
             "host_candidate/p261_all_method_census",
             "host_candidate/p263_operand_correlation",
             "host_candidate/p265_operand_shape"]
from p246_exception_semantics import need,decode,index,load
from p249_dual_diff import seal
from p253_cfg_ordinal import instructions
from p257_opcode_family import frame
from p259_all_operands import pair
from p261_all_method_census import method_observation,opaque
from p263_operand_correlation import changed_kind
from p265_operand_shape import report as shape_report,shape_cause

# Dalvik opcode and EXACT format: 35c (A/G, BBBB, C/D/E/F) or
# 3rc (AA, BBBB, CCCC). Both are 3 code units = SIX bytes.
FIXED={"invoke-virtual":0x6e,"invoke-super":0x6f,
       "invoke-direct":0x70,"invoke-static":0x71,"invoke-interface":0x72}
RANGE={name+"/range":value+6 for name,value in FIXED.items()}
NAMES={**FIXED,**RANGE}
CAUSES=("INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE",
        "INVOKE_WORD_SEQUENCE_CHANGED","INVOKE_WORD_COUNT_CHANGED",
        "INVOKE_METHOD_REFERENCE_CHANGED","INVOKE_REFERENCE_NOT_ATTESTED",
        "INVOKE_DESCRIPTOR_NOT_ATTESTED","INVOKE_WIDE_WORD_LAYOUT_INVALID",
        "INVOKE_REGISTER_FRAME_INVALID","INVOKE_DECODER_OPERANDS_UNATTESTED",
        "INVOKE_RAW_FORMAT_UNATTESTED","OTHER_ENCODING_FAMILY_NOT_ATTESTED",
        "MULTIPLE_INSTRUCTION_DIFFERENCES_NOT_ATTESTED")
class Unattested(Exception): pass

def raw_words(row):
    """Return (word registers, raw method index) or None; never emit values."""
    name,inst=row[1],row[3]
    if name not in NAMES:return None
    getter=getattr(inst,"get_raw",None)
    if not callable(getter):return None
    try:data=getter()
    except Exception:return None
    if not isinstance(data,(bytes,bytearray)) or len(data)!=6:return None
    if data[0]!=NAMES[name]:return None
    ref=data[2]|(data[3]<<8)
    if name in FIXED:
        count=data[1]>>4
        if count>5:return None
        registers=(data[4]&15,data[4]>>4,data[5]&15,data[5]>>4,data[1]&15)
        words=tuple(registers[:count])
    else:
        count=data[1]
        first=data[4]|(data[5]<<8)
        if first+count>65536:return None
        words=tuple(range(first,first+count))
    return words,ref

def reference(row,words,index):
    """Verify library-resolved METHOD reference and register view if exposed."""
    getter=getattr(row[3],"get_operands",None)
    if not callable(getter):return None
    try:seq=getter()
    except Exception:return None
    if not isinstance(seq,(list,tuple)) or len(seq)>256:return None
    refs=[];regs=[]
    for item in seq:
        if not isinstance(item,(list,tuple)) or len(item) not in (2,3):return None
        tag,val=item[0:2]
        if type(tag) is not int or type(val) is not int:return None
        if tag==0 and len(item)==2 and 0<=val<=65535:
            regs.append(val)
        elif 256<=tag<512 and len(item)==3 and val==index and isinstance(item[2],str) and 0<len(item[2])<=8192:
            refs.append((tag,item[2]))
        else:return None
    if len(refs)!=1:return None
    # Androguard may expand a range into all registers or expose its start.
    # Validate either exact expanded list, or range-start only. Never infer
    # a missing FIXED register from a partial library view.
    if row[1] in RANGE:
        if tuple(regs)!=words and not (len(regs)==1 and len(words)>0 and regs[0]==words[0]):
            if not (not regs and not words):return None
    elif tuple(regs)!=words:return None
    return refs[0]

def type_widths(resolved,static):
    """Parse a complete resolved method descriptor and count Dalvik WORDS."""
    if not isinstance(resolved,str):return None
    name="".join(resolved.split())
    k=name.find("(");e=name.find(")",k+1)
    if k<0 or e<0 or "->" not in name[:k] or not name.startswith("L"):return None
    args=name[k+1:e];ret=name[e+1:]
    if not ret:return None
    def parse(s,allow_void):
        widths=[];i=0
        while i<len(s):
            start=i
            while i<len(s) and s[i]=="[":i+=1
            if i==len(s):return None
            c=s[i]
            if c=="L":
                end=s.find(";",i+1)
                if end<0 or end==i+1:return None
                if not re.fullmatch(r"L[^;()\s]+;",s[i:end+1]):return None
                i=end+1
                width=1
            elif c in "ZBCSIFJD":
                i+=1;width=2 if c in "JD" and i==start+1 else 1
            elif c=="V" and allow_void and i==start and len(s)==1:
                i+=1;width=0
            else:return None
            widths.append(width)
        return widths
    params=parse(args,False)
    result=parse(ret,True)
    if params is None or result is None or len(result)!=1:return None
    return ([1] if not static else [])+params

def wide_valid(words,widths):
    if sum(widths)!=len(words):return False
    i=0
    for w in widths:
        if w==2 and (i+1>=len(words) or words[i+1]!=words[i]+1):
            return False
        i+=w
    return True

def classify(left,right,code_a,code_b):
    a,b=left[1],right[1]
    if a not in NAMES or b not in NAMES or a==b or a.removesuffix("/range")!=b.removesuffix("/range"):
        return "OTHER_ENCODING_FAMILY_NOT_ATTESTED"
    if (a in FIXED)==(b in FIXED):return "OTHER_ENCODING_FAMILY_NOT_ATTESTED"
    if frame(code_a,code_b)!="MATCH":return "INVOKE_REGISTER_FRAME_INVALID"
    try:
        sz=code_a.get_code().get_registers_size()
        oz=code_a.get_code().get_outs_size()
    except Exception:return "INVOKE_REGISTER_FRAME_INVALID"
    if type(sz) is not int or type(oz) is not int or sz<0 or sz>65535 or oz<0 or oz>65535:
        return "INVOKE_REGISTER_FRAME_INVALID"
    x,y=raw_words(left),raw_words(right)
    if x is None or y is None:return "INVOKE_RAW_FORMAT_UNATTESTED"
    wx,ix=x;wy,iy=y
    if len(wx)>oz or len(wy)>oz or any(r>=sz for r in wx+wy):
        return "INVOKE_REGISTER_FRAME_INVALID"
    rx,ry=reference(left,wx,ix),reference(right,wy,iy)
    if rx is None or ry is None:return "INVOKE_REFERENCE_NOT_ATTESTED"
    if rx[0]!=ry[0] or rx[1]!=ry[1]:return "INVOKE_METHOD_REFERENCE_CHANGED"
    # is_static is derived from the shared invoke kind, never just a side.
    widths=type_widths(rx[1],a.startswith("invoke-static"))
    if widths is None:return "INVOKE_DESCRIPTOR_NOT_ATTESTED"
    if len(wx)!=len(wy):return "INVOKE_WORD_COUNT_CHANGED"
    if sum(widths)!=len(wx) or not wide_valid(wx,widths) or not wide_valid(wy,widths):
        return "INVOKE_WIDE_WORD_LAYOUT_INVALID"
    if wx!=wy:return "INVOKE_WORD_SEQUENCE_CHANGED"
    return "INVOKE_WORD_SEQUENCE_MATCH_CANDIDATE"

def report(original,derived,da,db):
    prior=shape_report(original,derived,da,db)
    expected=prior["causes"]["NORMALIZED_ITEM_COUNT"]
    counts=Counter({k:0 for k in CAUSES})
    seen=0
    for key in sorted(original):
        a,b=original[key],derived[key]
        if a.get_code() is None:continue
        la,lb=decode(a,da),decode(b,db)
        if not method_observation(a,b,da,db,la,lb)["OPERANDS_STRUCTURED_DIFFER"]:continue
        if opaque(a) or opaque(b):continue
        ra,rb=instructions(a,la),instructions(b,lb)
        if len(ra)!=len(rb):continue
        different=[(x,y) for x,y in zip(ra,rb) if pair(x,y)=="STRUCTURED_DIFFER"]
        shape=[(x,y) for x,y in different if changed_kind(x,y)=="OPERAND_SHAPE"]
        if not shape or shape_cause(*shape[0])!="NORMALIZED_ITEM_COUNT":continue
        cause=(classify(*shape[0],a,b) if len(different)==1 and len(shape)==1
               else "MULTIPLE_INSTRUCTION_DIFFERENCES_NOT_ATTESTED")
        need(cause in CAUSES,"CAUSE")
        counts[cause]+=1;seen+=1
    need(seen==expected,"P265_P267_COUNT_RECONCILIATION")
    return dict(causes=dict(counts),examined=expected,unknown=prior["unknown_methods"],
                total_shapes=prior["shape_methods"])

def emit(q):
    need(type(q) is dict and set(q)=={"causes","examined","unknown","total_shapes"},"OUTPUT_SCHEMA")
    c=q["causes"];n=q["examined"]
    need(type(c) is dict and set(c)==set(CAUSES) and
         all(type(v) is int and 0<=v<=n for v in c.values()),"OUTPUT_CAUSES")
    need(all(type(q[k]) is int and 0<=q[k]<=1000000 for k in ("examined","unknown","total_shapes"))
         and n<=q["total_shapes"] and sum(c.values())==n,"OUTPUT_COUNTS")
    for key in CAUSES:print("P267_"+key+"="+str(c[key]))
    print("P267_NORMALIZED_ITEM_COUNT_METHODS="+str(n))
    print("P267_PREVIOUSLY_UNKNOWN_METHODS="+str(q["unknown"]))
    print("P267_PRIVATE_REGISTERS_AND_REFERENCES=WITHHELD")
    print("P267_PARAMETER_WORD_SEQUENCE_IS_NOT_ART_EQUIVALENCE=YES")
    print("P267_ORIGINAL_P245_FULL_GATE=NOT_ATTESTED")
    print("P267_RELEASE=DENY")
    print("P267_V139=STRUCTURAL_BLOCKED")
    return 2

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--signed-original",type=Path)
    ap.add_argument("--base",type=Path)
    ap.add_argument("--candidate",type=Path)
    a=ap.parse_args();paths=(a.signed_original,a.base,a.candidate)
    if all(x is None for x in paths):
        print("P267_SOURCE_ONLY=YES")
        print("P267_REAL_INVOKE_WORDS=NOT_ATTESTED")
        print("P267_RELEASE=DENY")
        print("P267_V139=STRUCTURAL_BLOCKED")
        return 0
    try:
        need(all(x is not None for x in paths),"THREE_PINNED_INPUTS")
        seal(a.signed_original)
        da,db=load(a.base),load(a.candidate)
        return emit(report(index(da),index(db),da,db))
    except Exception as exc:
        s=str(exc)
        if not re.fullmatch(r"P246_DENY_[A-Z0-9_]{3,96}",s):s="P267_DENY_UNEXPECTED"
        print(s,file=sys.stderr);return 2

if __name__=="__main__":raise SystemExit(main())
