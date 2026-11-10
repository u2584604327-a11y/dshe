#!/usr/bin/env python3
"""P209 signed-v138 PC414 branch audit, strictly static and read-only.

This scans only the exact published signed original APK. It never patches DEX,
executes the original app, reads account data, or infers real Android branches.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import zipfile

SIGNED_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
START="Lcom/dsh/android/EngineManager$start$2;"
DESC="(Ljava/lang/Object;)Ljava/lang/Object;"
START_PC=250
GUARD_PC=414
LAUNCH_PC=3912

class Denied(Exception):pass
def need(value,code):
    if not value:raise Denied("P209_PC414_DENY_"+code)

def register_operands(output):
    """DEX's if-ne format has exactly two explicit v-register operands."""
    operands=output.split(",",2)
    need(len(operands)>=2,"IF_NE_OPERAND_COUNT")
    result=[]
    for token in operands[:2]:
        match=re.fullmatch(r"\s*v([0-9]{1,3})\s*",token)
        need(match is not None,"IF_NE_REGISTER_FORMAT")
        result.append(int(match.group(1)))
    need(result[0]!=result[1],"IF_NE_IDENTICAL_OPERANDS")
    return tuple(result)

def classify_guard(edges,by_pc,start=START_PC,guard=GUARD_PC,goal=LAUNCH_PC):
    """Normal-control-flow proof only; branches are not runtime witnesses."""
    from audit_signed_process_prelaunch import path_avoiding
    need(start in by_pc and guard in by_pc and goal in by_pc,
         "EXPECTED_INSTRUCTION_BOUNDARIES")
    need(by_pc[guard]["op"]=="if-ne","GUARD_OPCODE_DRIFT")
    successors=edges.get(guard,())
    need(len(successors)==2 and all(x in by_pc for x in successors),
         "BRANCH_TWO_SUCCESSORS")
    need(path_avoiding(edges,start,guard),"GUARD_NOT_REACHABLE_FROM_PC250")
    fall=guard+by_pc[guard]["length"]
    need(fall in successors,"GUARD_FALLTHROUGH_DRIFT")
    taken=next(x for x in successors if x!=fall)
    reach_fall=path_avoiding(edges,fall,goal)
    reach_taken=path_avoiding(edges,taken,goal)
    need(reach_fall != reach_taken,"GUARD_NOT_SPLIT_TO_PC3912")
    bypass=path_avoiding(edges,start,goal,forbidden=guard)
    return (fall,taken,reach_fall,reach_taken,bypass)

WRITE_PREFIXES=("move","const","new-instance","new-array","iget",
                "sget","aget","array-length","instance-of","check-cast",
                "neg-","not-","int-to","long-to","float-to","double-to",
                "add-","sub-","mul-","div-","rem-","and-","or-","xor-",
                "shl-","shr-","ushr-","rsub-","cmp")
def lexical_writes(rows,reg,start=START_PC,end=GUARD_PC):
    """Candidates in textual order; intentionally NOT reaching definitions."""
    hits=[]
    for pc,ins in rows:
        if not start<=pc<end:continue
        op=ins.get_name()
        if not op.startswith(WRITE_PREFIXES):continue
        match=re.match(r"\s*v([0-9]{1,3})(?=\s*[,\s]|$)",ins.get_output())
        if match and int(match.group(1))==reg:
            hits.append((pc,op))
    return hits[-3:]

def inspect_signed(apk):
    from androguard.core.dex import DEX
    import pathlib
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/
                          "p204_oncreate_pc430"))
    import audit_original_oncreate_pc430 as cfg
    src=Path(apk)
    need(src.is_file() and not src.is_symlink(),"PINNED_APK_EXISTS")
    need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,
         "SIGNED_V138_SHA256")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None,"SIGNED_APK_CRC")
        names=sorted(n for n in z.namelist() if
                     re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(names==["classes.dex","classes2.dex"],"SIGNED_DEX_INVENTORY")
        dex=DEX(z.read("classes.dex"))
    methods=[m for c in dex.get_classes() if c.get_name()==START
             for m in c.get_methods() if m.get_name()=="invokeSuspend"
             and "".join(m.get_descriptor().split())==DESC]
    need(len(methods)==1,"START2_UNIQUE_SIGNATURE")
    rows=list(methods[0].get_instructions_idx())
    code={pc:ins for pc,ins in rows}
    need(GUARD_PC in code and code[GUARD_PC].get_name()=="if-ne",
         "PINNED_PC414_IF_NE")
    regs=register_operands(code[GUARD_PC].get_output())
    nodes=[cfg.instruction(pc,i.get_name(),i.get_length(),
           i.get_ref_off() if cfg.is_cond(i.get_name()) or
           cfg.is_jump(i.get_name()) else None) for pc,i in rows]
    edges,unknown,by_pc=cfg.graph(nodes)
    need(not unknown,"UNMODELED_SWITCH_OR_PAYLOAD")
    fall,taken,fr,tr,bypass=classify_guard(edges,by_pc)
    # Signed-DEX source metadata, not runtime result values. DEX move-result
    # must immediately follow the producing invoke, or fail closed.
    need(412 in code and code[412].get_name()=="move-result-object",
         "GUARD_V10_RESULT_SITE_DRIFT")
    sequence=[pc for pc,_ in rows]
    idx=sequence.index(412)
    need(idx>0,"MOVE_RESULT_NO_PREDECESSOR")
    producer_pc=sequence[idx-1]
    producer=code[producer_pc]
    need(producer_pc+producer.get_length()==412 and
         producer.get_name().startswith("invoke-"),
         "GUARD_V10_NOT_ADJACENT_INVOKE_RESULT")
    callee=re.search(r"L[^;,\\s]{1,130};->[A-Za-z0-9_$<>]{1,70}\\(",
                     producer.get_output())
    callee_text=callee.group(0)[:-1] if callee else "NOT_UNIQUELY_DECODED"
    need(len(callee_text)<=220,"GUARD_V10_CALLEE_BOUND")
    need(fall in code and taken in code,"BRANCH_DESTINATIONS_MISSING")
    previous_v2=lexical_writes(rows,regs[1],start=0,end=GUARD_PC)
    # This inventory does not prove the live register contents. Control-flow
    # merges, unmodeled wide/alias writes and exception handlers still apply.
    # Only the conditional's exact two graph edges are claimed. Do not
    # assert that Android reached PC414, or that the other edge is terminal.
    print("P209_PC414_SIGNED_V138_EXACT_OPCODE=if-ne")
    print("P209_PC414_BRANCH_OPERAND_COUNT=2")
    print("P209_PC414_FALL_PC="+str(fall))
    print("P209_PC414_TAKEN_PC="+str(taken))
    print("P209_PC414_FALL_OPCODE="+code[fall].get_name())
    print("P209_PC414_TAKEN_OPCODE="+code[taken].get_name())
    print("P209_PC414_OPERAND_1_PRODUCER_PC="+str(producer_pc))
    print("P209_PC414_OPERAND_1_PRODUCER_OP="+producer.get_name())
    print("P209_PC414_OPERAND_1_PRODUCER_STATIC_CALLEE="+callee_text)
    print("P209_PC414_OPERAND_2_PRE_PC414_LEXICAL_LAST3_COUNT="+
          str(len(previous_v2)))
    for at,op in previous_v2:
        print("P209_PC414_OPERAND_2_PRE_PC414_LEXICAL_WRITE_PC="+
              str(at)+",OP="+op)
    print("P209_PC414_FALL_PC3912="+
          ("REACHABLE_IN_NORMAL_CFG" if fr else "NOT_REACHABLE_IN_MODELED_CFG"))
    print("P209_PC414_TAKEN_PC3912="+
          ("REACHABLE_IN_NORMAL_CFG" if tr else "NOT_REACHABLE_IN_MODELED_CFG"))
    print("P209_PC250_PC3912_BYPASS_PC414="+
          ("POSSIBLE_IN_NORMAL_CFG" if bypass else "NOT_FOUND_IN_MODELED_CFG"))
    for n,reg in enumerate(regs,1):
        writers=lexical_writes(rows,reg)
        print("P209_PC414_OPERAND_"+str(n)+"_REGISTER=v"+str(reg))
        print("P209_PC414_OPERAND_"+str(n)+"_LEXICAL_WRITE_COUNT_LAST3="+
              str(len(writers)))
        for at,op in writers:
            print("P209_PC414_OPERAND_"+str(n)+
                  "_LEXICAL_WRITER_PC="+str(at)+",OP="+op)
        print("P209_PC414_OPERAND_"+str(n)+"_REACHING_DEFINITION=NOT_ATTESTED")
    print("P209_PC414_EXCEPTION_AND_RUNTIME_BRANCH=NOT_ATTESTED")
    print("P209_PC414_NO_PRODUCTION_OR_ORIGINAL_DEX_MODIFICATION=YES")
    print("P209_PC414_RELEASE=STRUCTURAL_BLOCKED")
    print("P209_SIGNED_PC414_STATIC_BRANCH_AUDIT=PASS")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("signed_original_v138")
    args=ap.parse_args()
    try:inspect_signed(args.signed_original_v138)
    except Denied as error:
        print(str(error),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_PC414_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
