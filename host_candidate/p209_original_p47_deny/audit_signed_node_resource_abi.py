#!/usr/bin/env python3
"""P209 signed-v138 Node resource/ABI evidence, read-only, bounded, fail-closed.

No original DEX edits, Node execution, host process launch, Android account
access, or output of original ZIP entry names, string literals, path arguments.
ZIP name/ABI indicators are HINTS, not proof of installability or compatibility.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import SIGNED_SHA,BOOT,need,normalize_descriptor,Denied
from audit_signed_node_locked import resolve_method
from audit_signed_node_delegate import safe_invoke_symbol,static_call_inventory

APP_SIG=(
    "getNodeBinary",
    "nodeIsUsable",
)
NODE=re.compile(r"(?:^|[/_.-])node(?:js)?(?=$|[/_.-])",re.IGNORECASE)
ABI=re.compile(r"(?:^|[/_.-])(arm64-v8a|armeabi-v7a|x86_64|x86)(?=$|[/_.-])",re.IGNORECASE)
ARCHIVE_END=(".zip",".tar",".tar.gz",".tgz",".tar.xz",".txz",".xz",".gz",".zst")
MACHINES={183:"ARM64_ELF",40:"ARM32_ELF",62:"X86_64_ELF",3:"X86_ELF"}

def apk_inventory(infos):
    """Only aggregated ZIP entry metadata, never path/name output."""
    nodes=[]
    top=Counter()
    abis=Counter()
    archives=0
    total=0
    for item in infos:
        path=item.filename
        if item.is_dir():continue
        total+=1
        need(total<=100000,"ZIP_ENTRY_COUNT_BOUND")
        top[path.split("/",1)[0] if "/" in path else "ROOT"]+=1
        match=ABI.search(path)
        if match:abis[match.group(1).lower()]+=1
        if NODE.search(path):
            nodes.append(item)
            if path.lower().endswith(ARCHIVE_END):archives+=1
    need(len(nodes)<=5000,"NODE_FILENAME_HINT_COUNT_BOUND")
    return total,top,abis,nodes,archives

def elf_abi(header):
    """Only parse 20 bytes of a candidate ZIP member; no execution."""
    if len(header)<20 or header[:4]!=b"\x7fELF":
        return "NO_DIRECT_ELF_HEADER"
    if header[5] not in (1,2):
        return "UNRECOGNIZED_ELF_ENDIAN"
    machine=int.from_bytes(header[18:20],
                           "little" if header[5]==1 else "big")
    return MACHINES.get(machine,"OTHER_ELF_MACHINE")

def direct_sites(rows):
    """Owner-only classifications, never method arguments or raw strings."""
    counters=Counter()
    relevant=[]
    for pc,inst in rows:
        op=inst.get_name()
        if op.startswith("invoke-"):
            symbol=safe_invoke_symbol(inst.get_output())
            if symbol is None:continue
            owner,method=symbol
            if owner=="Landroid/content/res/AssetManager;":
                kind="DIRECT_ASSET_MANAGER_CALL"
            elif owner.startswith(("Ljava/util/zip/","Ljava/util/jar/")):
                kind="DIRECT_ARCHIVE_OWNER_CALL"
            elif owner.startswith(("Ljava/security/","Ljavax/crypto/")):
                kind="DIRECT_HASH_CRYPTO_OWNER_CALL"
            elif owner in ("Landroid/os/Build;","Ljava/lang/System;"):
                kind="DIRECT_ENV_API_CALL"
            elif owner=="Ljava/lang/ProcessBuilder;" and method=="start":
                kind="DIRECT_PROCESS_BUILDER_START"
            elif owner=="Ljava/lang/Runtime;" and method=="exec":
                kind="DIRECT_RUNTIME_EXEC"
            else:continue
            counters[kind]+=1
            relevant.append((pc,kind))
        elif op.startswith(("sget","iget")) and (
            "Landroid/os/Build;->SUPPORTED_ABIS" in inst.get_output() or
            "Landroid/os/Build;->CPU_ABI" in inst.get_output()):
            counters["DIRECT_ABI_FIELD_READ"]+=1
            relevant.append((pc,"DIRECT_ABI_FIELD_READ"))
    need(len(relevant)<=100,"RELEVANT_SITE_BOUND")
    return counters,relevant

def linked_method_candidates(dexes,locked_rows,method_name):
    """Match unique signed-v138 callee *descriptor* actually invoked by locked."""
    found=[]
    for dex_name,dex in dexes:
        for cls in dex.get_classes():
            if cls.get_name()!=BOOT:continue
            for method in cls.get_methods():
                if method.get_name()!=method_name or method.get_code() is None:
                    continue
                descriptor=normalize_descriptor(method.get_descriptor())
                target=BOOT+"->"+method_name+descriptor
                invokes=[pc for pc,ins in locked_rows
                         if ins.get_name().startswith("invoke-") and
                         target in normalize_descriptor(ins.get_output())]
                if invokes:found.append((dex_name,method,invokes))
    need(len(found)==1,"SIGNED_LINKED_"+method_name+"_UNIQUE")
    need(found[0][0]=="classes.dex","SIGNED_LINKED_HELPER_PRIMARY")
    need(len(found[0][2])<=32,"SIGNED_HELPER_CALLSITE_BOUND")
    return found[0]

def method_shape(method):
    rows=list(method.get_instructions_idx())
    need(1<=len(rows)<=12000,"METHOD_INSTRUCTION_BOUND")
    returns=[pc for pc,ins in rows if ins.get_name().startswith("return")]
    branches=[pc for pc,ins in rows if
              ins.get_name().startswith(("goto","if-"))]
    tries=len(method.get_code().get_tries() or [])
    need(0<=tries<=256 and 1<=len(returns)<=128,
         "METHOD_RETURN_AND_TRY_BOUND")
    counts,sites=direct_sites(rows)
    return rows,len(returns),len(branches),tries,counts,sites

def audit(apk):
    from androguard.core.dex import DEX
    source=Path(apk)
    need(source.is_file() and not source.is_symlink(),"APK_FILE")
    need(hashlib.sha256(source.read_bytes()).hexdigest()==SIGNED_SHA,
         "SIGNED_V138_SHA256")
    with zipfile.ZipFile(source) as z:
        need(z.testzip() is None,"SIGNED_ZIP_CRC")
        members=sorted(n for n in z.namelist() if
                       re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(members==["classes.dex","classes2.dex"],"SIGNED_DEX_INVENTORY")
        dexes=[(n,DEX(z.read(n))) for n in members]
        total,top,abis,nodes,archives=apk_inventory(z.infolist())
        elfs=Counter()
        for info in nodes:
            need(info.file_size<=1000000000,"NODE_HINT_ENTRY_SIZE_BOUND")
            with z.open(info,"r") as entry:
                elfs[elf_abi(entry.read(20))]+=1
    dex_name,locked=resolve_method(dexes,BOOT,"installNodeRuntimeLocked")
    need(dex_name=="classes.dex","SIGNED_LOCKED_BODY_PRIMARY")
    locked_rows,_,_,_,locked_count,locked_sites=method_shape(locked)
    linked=[]
    for name in APP_SIG:
        helper_dex,method,invoke_pcs=linked_method_candidates(
            dexes,locked_rows,name)
        _,nret,nbranch,ntry,counts,sites=method_shape(method)
        linked.append((name,invoke_pcs,nret,nbranch,ntry,counts,sites))
    print("P209_NODE_RESOURCE_APK_SHA256_PIN=PASS")
    print("P209_NODE_RESOURCE_APK_ZIP_CRC=PASS")
    print("P209_NODE_RESOURCE_SIGNED_ZIP_MEMBER_COUNT="+str(total))
    for key in ("assets","lib","res"):
        print("P209_NODE_RESOURCE_ZIP_TOP_"+key.upper()+"_COUNT="+str(top[key]))
    print("P209_NODE_RESOURCE_FILENAME_HINT_COUNT="+str(len(nodes)))
    print("P209_NODE_RESOURCE_ARCHIVE_FILENAME_HINT_COUNT="+str(archives))
    for abi in ("arm64-v8a","armeabi-v7a","x86_64","x86"):
        print("P209_NODE_RESOURCE_ZIP_ABI_PATH_HINT_"+abi.replace("-","_").upper()+
              "="+str(abis[abi]))
    for key in ("ARM64_ELF","ARM32_ELF","X86_64_ELF","X86_ELF",
                "OTHER_ELF_MACHINE","NO_DIRECT_ELF_HEADER",
                "UNRECOGNIZED_ELF_ENDIAN"):
        print("P209_NODE_RESOURCE_CANDIDATE_"+key+"="+str(elfs[key]))
    print("P209_NODE_RESOURCE_FILENAME_HINTS_DO_NOT_PROVE_NODE_ARCH=YES")
    print("P209_NODE_RESOURCE_ORIGINAL_CODE_LOCKED=EXACT_SIGNED_DEX")
    for kind in ("DIRECT_ASSET_MANAGER_CALL","DIRECT_ARCHIVE_OWNER_CALL",
                 "DIRECT_HASH_CRYPTO_OWNER_CALL","DIRECT_ENV_API_CALL",
                 "DIRECT_ABI_FIELD_READ","DIRECT_PROCESS_BUILDER_START",
                 "DIRECT_RUNTIME_EXEC"):
        print("P209_NODE_RESOURCE_LOCKED_"+kind+"="+str(locked_count[kind]))
    for pc,kind in locked_sites:
        print("P209_NODE_RESOURCE_LOCKED_STATIC_PC="+str(pc)+",KIND="+kind)
    for name,invoke_pcs,nret,nbranch,ntry,counts,sites in linked:
        print("P209_NODE_RESOURCE_HELPER_"+name+"_LINKED_CALL_COUNT="+
              str(len(invoke_pcs)))
        print("P209_NODE_RESOURCE_HELPER_"+name+"_RETURN_COUNT="+str(nret))
        print("P209_NODE_RESOURCE_HELPER_"+name+"_BRANCH_COUNT="+str(nbranch))
        print("P209_NODE_RESOURCE_HELPER_"+name+"_TRY_COUNT="+str(ntry))
        for kind in ("DIRECT_ASSET_MANAGER_CALL","DIRECT_ARCHIVE_OWNER_CALL",
                     "DIRECT_HASH_CRYPTO_OWNER_CALL","DIRECT_ENV_API_CALL",
                     "DIRECT_ABI_FIELD_READ","DIRECT_PROCESS_BUILDER_START",
                     "DIRECT_RUNTIME_EXEC"):
            print("P209_NODE_RESOURCE_HELPER_"+name+"_"+kind+"="+str(counts[kind]))
    print("P209_NODE_RESOURCE_TRUSTED_EXPECTED_NODE_PAYLOAD_HASH=NOT_PROVIDED")
    print("P209_NODE_RESOURCE_PAYLOAD_NESTED_ARCHIVE_ELF=NOT_INSPECTED")
    print("P209_NODE_RESOURCE_RUNTIME_DEVICE_ABI=NOT_ATTESTED")
    print("P209_NODE_RESOURCE_ACTUAL_INSTALL_OR_RUN=NOT_ATTESTED")
    print("P209_NODE_RESOURCE_ORIGINAL_DEX_MODIFIED=NO")
    print("P209_NODE_RESOURCE_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P209_NODE_RESOURCE_ORIGINAL_V138_STATIC_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    args=p.parse_args()
    try:audit(args.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr)
        sys.exit(2)
    except Exception:
        print("P209_NODE_RESOURCE_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
