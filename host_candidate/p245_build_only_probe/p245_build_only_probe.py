#!/usr/bin/env python3
"""P245 disposable build-only probe. DEX parse success is not ART verification."""
import argparse,hashlib,re,sys,zipfile
from pathlib import Path
sys.path.insert(0,"host_candidate/p209_original_p47_deny")
from p210_optional_node_usability import scope as base_scope,load_dex,method_index,exception_structure,need
SRC=Path(".p43tmp/decoded/smali/com/dsh/android/EngineManager$start$2.smali")
SIGN=Path(".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
BASE=Path(".p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk")
SEAL=Path(".p245tmp/source.sha256")
OWNER="Lcom/dsh/android/EngineManager$start$2;"
NAME="p245Observe$ci"
DESC="("+OWNER+")V"
GETTER="Lcom/dsh/android/EngineManager;->access$getProcess$p(Lcom/dsh/android/EngineManager;)Ljava/lang/Process;"
OLD="    invoke-static {}, Lcom/dsh/android/p209/P209PreCallWitness;->markPostThrowOnFailure()V"
NEW="    invoke-static/range {p0 .. p0}, "+OWNER+"->"+NAME+DESC
CAP=re.compile(r"(?m)^\s*\.field [^\n]*\s+([^\s:]+):Lcom/dsh/android/EngineManager;\s*$")
def captured(s):
    fs=CAP.findall(s)
    need(len(fs)==1 and re.fullmatch(r"[A-Za-z_$][A-Za-z_0-9$]*",fs[0]),"ONE_ENGINE_CAPTURE")
    return fs[0]
def helper(f):
    return (
      "\n.method public static "+NAME+DESC+"\n"
      "    .registers 5\n"
      "    :try_start_0\n"
      "    iget-object v0, p0, "+OWNER+"->"+f+":Lcom/dsh/android/EngineManager;\n"
      "    if-eqz v0, :is_null\n"
      "    invoke-static {v0}, "+GETTER+"\n"
      "    move-result-object v0\n"
      "    if-eqz v0, :is_null\n"
      "    const-string v1, \"P245_STATE\"\n"
      "    const-string v2, \"PROCESS_NON_NULL\"\n"
      "    goto :emit\n"
      "    :is_null\n"
      "    const-string v1, \"P245_STATE\"\n"
      "    const-string v2, \"PROCESS_NULL\"\n"
      "    :emit\n"
      "    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I\n"
      "    :try_end_0\n"
      "    .catch Ljava/lang/Throwable; {:try_start_0 .. :try_end_0} :caught\n"
      "    return-void\n"
      "    :caught\n"
      "    move-exception v0\n"
      "    return-void\n"
      ".end method\n"
    )
def patched(s):
    need(s.count(OLD)==1 and NEW not in s and NAME not in s,"EXACT_OLD_MARKER")
    need(bool(re.search(r"(?m)^\.class[^\n]* Lcom/dsh/android/EngineManager\$start\$2;$",s)),"CLASS")
    need(GETTER in s,"ORIGINAL_GETTER")
    f=captured(s)
    out=s.replace(OLD,NEW,1).rstrip("\n")+"\n"+helper(f)
    need(restored(out)==s.rstrip("\n")+"\n","REVERSIBLE")
    return out
def restored(s):
    need(s.count(NEW)==1 and OLD not in s,"EXACT_NEW_MARKER")
    h=helper(captured(s))
    need(s.endswith(h) and s.count(h)==1,"EXACT_HELPER_END")
    return s[:-len(h)].replace(NEW,OLD,1)
def scope():
    base_scope()
    need(SRC.is_file() and not SRC.is_symlink(),"TEMP_SOURCE_ONLY")
def patch():
    scope()
    need(not SEAL.exists(),"NOT_ALREADY_PATCHED")
    old=SRC.read_bytes()
    result=patched(old.decode())
    SEAL.parent.mkdir(parents=True,exist_ok=True)
    SEAL.write_text(hashlib.sha256(old).hexdigest()+"\n")
    SRC.write_text(result)
    print("P245_ORIGINAL_PC176_EXISTING_35C_TO_3RC=PATCHED_TEMP")
def restore():
    scope()
    need(SEAL.is_file(),"SEAL")
    s=restored(SRC.read_text())
    SRC.write_text(s)
    need(hashlib.sha256(SRC.read_bytes()).hexdigest()==SEAL.read_text().strip(),"RESTORE_BYTES")
    SEAL.unlink()
    print("P245_TEMP_SMALI_RESTORE=BYTE_EXACT")
def ins(m):
    return [(pc,i.get_name(),i.get_length(),i.get_output()) for pc,i in m.get_instructions_idx()]
def semantic_exceptions(method,dex):
    """Canonical try spans and ordered typed/catch-all targets, not pool indices."""
    code=method.get_code()
    if code is None:return None
    tries=code.get_tries() or []
    table=code.get_handlers()
    if not tries:
        need(code.get_tries_size()==0 and (table is None or table.get_size()==0),
             "EMPTY_EXCEPTION_TABLE_PARITY")
        return ()
    need(table is not None and len(tries)==code.get_tries_size(),"CATCH_LIST_EXISTS")
    origin=table.get_off()
    handlers={}
    valid={pc//2 for pc,_ in method.get_instructions_idx()}
    total=code.get_insns_size()
    for h in table.get_list():
        offset=h.get_off()-origin
        need(type(offset) is int and offset>=1 and offset not in handlers,
             "CATCH_OFF_UNIQUE")
        typed=[]
        for pair in (h.get_handlers() or []):
            typ=dex.get_cm_type(pair.get_type_idx())
            need(type(typ) is str and typ.startswith("L") and typ.endswith(";"),
                 "CATCH_TYPE_RESOLVED")
            need(pair.get_addr() in valid,"CATCH_TARGET_ALIGNED")
            typed.append((typ,pair.get_addr()))
        catchall=h.get_catch_all_addr() if h.get_size()<=0 else None
        if catchall is not None:need(catchall in valid,"CATCHALL_TARGET_ALIGNED")
        need(typed or catchall is not None,"NONEMPTY_HANDLER")
        handlers[offset]=(tuple(typed),catchall)
    need(len(handlers)==table.get_size(),"CATCH_COUNT")
    normalized=[]
    for t in tries:
        start=t.get_start_addr();end=start+t.get_insn_count()
        need(start in valid and (end in valid or end==total) and end>start,
             "TRY_BOUNDARIES_ALIGNED")
        off=t.get_handler_off()
        need(off in handlers,"TRY_OFF_RESOLVED")
        normalized.append((start,t.get_insn_count(),handlers[off]))
    return tuple(normalized)

def verify(candidate):
    scope()
    need(not SEAL.exists() and SRC.read_text().count(OLD)==1,"RESTORED_FIRST")
    need(candidate.is_file() and not candidate.is_symlink(),"UNSIGNED_APK")
    si=method_index(load_dex(SIGN))
    base_dex=load_dex(BASE)
    candidate_dex=load_dex(candidate)
    bi=method_index(base_dex)
    ci=method_index(candidate_dex)
    target=(OWNER,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;")
    witness=(OWNER,NAME,DESC)
    need(target in si and target in bi and witness not in bi and
         set(ci)-set(bi)=={witness} and set(bi)<=set(ci),"SINGLE_ADDED_HELPER")
    bypc={pc:i for pc,i in si[target].get_instructions_idx()}
    need(194 in bypc and GETTER in bypc[194].get_output(),"SIGNED_PC194_GETTER")
    changes=0
    for key,bm in bi.items():
        cm=ci[key]
        need((bm.get_code() is None)==(cm.get_code() is None),"CODE_EXISTENCE")
        if bm.get_code() is None:continue
        b,c=ins(bm),ins(cm)
        need(len(b)==len(c),"ORIGINAL_INSTRUCTION_COUNT")
        bc,cc=bm.get_code(),cm.get_code()
        need((bc.get_registers_size(),bc.get_ins_size(),bc.get_outs_size())==
             (cc.get_registers_size(),cc.get_ins_size(),cc.get_outs_size()),"ORIGINAL_REGISTERS")
        need(semantic_exceptions(bm,base_dex)==semantic_exceptions(cm,candidate_dex),
             "ORIGINAL_EXCEPTION_SEMANTICS")
        diff=[(x,y) for x,y in zip(b,c) if x!=y]
        if key==target:
            need(len(diff)==1,"ONE_EXISTING_SLOT")
            x,y=diff[0]
            need(x[0]==y[0] and x[2]==y[2]==6 and x[1]=="invoke-static" and
                 y[1]=="invoke-static/range" and
                 "P209PreCallWitness;->markPostThrowOnFailure()V" in x[3] and
                 OWNER+"->"+NAME+DESC in y[3],"EXACT_35C_TO_3RC")
            changes+=1
        else:need(not diff,"OTHER_METHOD_CHANGED")
        oldby=dict(bm.get_instructions_idx())
        newby=dict(cm.get_instructions_idx())
        for (pc,op,n,_),(newpc,newop,newn,_) in zip(b,c):
            need(pc==newpc and n==newn,"PC_WIDTH")
            if op.startswith("if-") or op.startswith("goto") or op in ("packed-switch","sparse-switch"):
                need(op==newop and oldby[pc].get_ref_off()==newby[newpc].get_ref_off() and
                     oldby[pc].get_output()==newby[newpc].get_output(),"BRANCH_OPERANDS_TARGETS")
    need(changes==1,"EXACT_ONE_REPLACEMENT")
    h=ci[witness]
    hr=ins(h)
    output="\n".join(x[3] for x in hr)
    need(h.get_code().get_tries_size()==1 and
         sum(x[1]=="iget-object" for x in hr)==1 and
         sum(x[1]=="invoke-static" for x in hr)==2 and
         GETTER in output and
         "Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I" in output,
         "HELPER_TYPED_READ_AND_CATCH")
    with zipfile.ZipFile(BASE) as b,zipfile.ZipFile(candidate) as c:
        need(b.testzip() is None and c.testzip() is None,"ZIP")
        need(b.read("classes3.dex")==c.read("classes3.dex"),"THIRD_DEX")
        need(b.read("AndroidManifest.xml")==c.read("AndroidManifest.xml"),"MANIFEST")
    for line in (
      "P245_SIGNED_PC194_TYPED_PROCESS_GETTER=PASS",
      "P245_ONE_EXISTING_MARKER_SAME_WIDTH=PASS",
      "P245_ALL_ORIGINAL_BRANCH_OPERANDS_TARGETS=PARITY",
      "P245_ORIGINAL_TRY_HANDLERS_REGISTERS=PARITY",
      "P245_ONE_CATCH_GUARDED_PROCESS_READ_HELPER=PASS",
      "P245_P47_THIRD_DEX_MANIFEST=UNCHANGED",
      "P245_ART_VERIFIER_ACCEPTANCE=NOT_ATTESTED",
      "P245_RUNTIME_PROCESS_STATE=NOT_ATTESTED",
      "P245_NO_THROW_RESOLUTION=NOT_ATTESTED",
      "P245_ANDROID_EMULATOR_OR_PHONE_INSTALLED=NO",
      "P245_V139=STRUCTURAL_BLOCKED",
      "P245_STATIC_BUILD_ONLY=PASS"):
        print(line)
def main():
    parser=argparse.ArgumentParser()
    g=parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--patch",action="store_true")
    g.add_argument("--restore",action="store_true")
    g.add_argument("--verify")
    a=parser.parse_args()
    try:
        if a.patch:patch()
        elif a.restore:restore()
        else:verify(Path(a.verify))
    except Exception as exc:
        code=str(exc)
        if not re.fullmatch(r"[A-Z0-9_]{3,120}",code):
            code="UNEXPECTED"
        print("P245_BUILD_ONLY_DENY_CODE="+code,file=sys.stderr)
        return 2
    return 0
if __name__=="__main__":raise SystemExit(main())
