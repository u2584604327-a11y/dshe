#!/usr/bin/env python3
"""P216: signed-v138 MainActivity ActivityResult contract attribution, STATIC.

Verify original signed APK, then inspect exact DEX invoke owners and class
construction plus MainActivity launcher field references. Every field-match
is a static proximity HINT, not a proved receiver/value-flow relation.
Never outputs permission values, field names, raw DEX operand strings,
intent extras, account data, sensitive method names or user data.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import SIGNED_SHA,need,Denied
from p215_signed_runtime_permissions import class_call,APP

MAIN="Lcom/dsh/android/MainActivity;"
LAUNCHER="Landroidx/activity/result/ActivityResultLauncher;"
CONTRACT_ROOT="Landroidx/activity/result/contract/ActivityResultContracts$"
CONTRACTS={
    CONTRACT_ROOT+"RequestPermission;":"REQUEST_ONE",
    CONTRACT_ROOT+"RequestMultiplePermissions;":"REQUEST_MULTIPLE",
    CONTRACT_ROOT+"StartActivityForResult;":"START_ACTIVITY",
    CONTRACT_ROOT+"GetContent;":"GET_CONTENT",
    CONTRACT_ROOT+"OpenDocument;":"OPEN_DOCUMENT",
    CONTRACT_ROOT+"TakePicture;":"TAKE_PICTURE",
}
CALL_BOUND=256
FIELD_REF=re.compile(
    r"Lcom/dsh/android/MainActivity;->([A-Za-z0-9_$]{1,100}):"
    r"Landroidx/activity/result/ActivityResultLauncher;")
CATEGORIES=("PERMISSION_CONTRACT_NEW","OTHER_CONTRACT_NEW",
            "CONTRACT_CONSTRUCTOR_INVOKE","ACTIVITY_RESULT_REGISTER",
            "GENERIC_LAUNCH","LAUNCHER_FIELD_GET","LAUNCHER_FIELD_SET")

def owner_class(caller):
    if caller==MAIN:return "MAIN_ACTIVITY"
    if caller.startswith("Lcom/dsh/android/MainActivity$"):
        return "MAIN_NESTED"
    if caller.startswith(APP):return "OTHER_ORIGINAL_APP"
    return "BUNDLED_LIBRARY"

def event_for(ins,fieldnames):
    op=ins.get_name()
    output=ins.get_output()
    m=FIELD_REF.search(output) if op in ("iget-object","iput-object",
                                         "sget-object","sput-object") else None
    if m and m.group(1) in fieldnames:
        return ("LAUNCHER_FIELD_GET" if op.startswith(("iget","sget"))
                else "LAUNCHER_FIELD_SET"),fieldnames[m.group(1)]
    if op=="new-instance":
        for target,type_label in CONTRACTS.items():
            if target in output:
                return ("PERMISSION_CONTRACT_NEW"
                        if type_label.startswith("REQUEST_") else
                        "OTHER_CONTRACT_NEW"),type_label
        return None
    ref=class_call(ins)
    if ref is None:return None
    owner,name=ref
    if owner in CONTRACTS and name=="<init>":
        return "CONTRACT_CONSTRUCTOR_INVOKE",CONTRACTS[owner]
    if name=="registerForActivityResult" and (
        owner.startswith("Landroidx/activity/") or
        owner.startswith("Landroidx/fragment/") or
        owner==MAIN):
        return "ACTIVITY_RESULT_REGISTER","REGISTRATION"
    if owner==LAUNCHER and name=="launch":
        return "GENERIC_LAUNCH","LAUNCH"
    return None

def launcher_fields(cls):
    match=[f for f in cls.get_fields()
           if "".join(f.get_descriptor().split())==LAUNCHER]
    names=sorted(f.get_name() for f in match)
    need(len(names)==len(set(names)) and len(names)<=64,
         "LAUNCHER_FIELD_UNIQUE_BOUND")
    return {name:index+1 for index,name in enumerate(names)}

def extract_events(dexes):
    main_classes=[c for _,dex in dexes for c in dex.get_classes()
                  if c.get_name()==MAIN]
    need(len(main_classes)==1,"SINGLE_MAIN_ACTIVITY_CLASS")
    fields=launcher_fields(main_classes[0])
    events=[]
    launch_windows=[]
    scanned=0
    for dex_name,dex in dexes:
        for cls in dex.get_classes():
            caller=cls.get_name()
            for method in cls.get_methods():
                if method.get_code() is None:continue
                scanned+=1
                need(scanned<=100000,"METHOD_SCAN_BOUND")
                rows=list(method.get_instructions_idx())
                local=[]
                for i,(pc,ins) in enumerate(rows):
                    ev=event_for(ins,fields)
                    if ev is None:continue
                    label,detail=ev
                    events.append((dex_name,owner_class(caller),caller,
                                   method.get_name(),pc,label,detail))
                    need(len(events)<=CALL_BOUND,"BOUNDED_EVENT_COUNT")
                    local.append((pc,label,detail))
                    if caller==MAIN and label=="GENERIC_LAUNCH":
                        # Strictly a local proximity heuristic. No implication
                        # that the field was actually passed as the receiver.
                        nearby=[entry[2] for entry in local
                                if entry[1]=="LAUNCHER_FIELD_GET" and
                                0<=pc-entry[0]<=64]
                        launch_windows.append((pc,tuple(sorted(set(nearby)))))
    need(scanned>0,"DEX_CODE_PRESENT")
    return fields,events,launch_windows,scanned

def field_hints(events,launch_windows):
    # Two independent hints: a MainActivity method containing registration and
    # a permission contract new; a field-set in THAT SAME method. Not dataflow.
    grouped={}
    for dex,category,cls,meth,pc,label,detail in events:
        if category!="MAIN_ACTIVITY":continue
        grouped.setdefault((cls,meth),[]).append((pc,label,detail))
    candidates=set()
    for rows in grouped.values():
        if (any(kind=="PERMISSION_CONTRACT_NEW" for _,kind,_ in rows)
            and any(kind=="ACTIVITY_RESULT_REGISTER" for _,kind,_ in rows)):
            candidates.update(detail for _,kind,detail in rows
                              if kind=="LAUNCHER_FIELD_SET")
    matches=sum(1 for _,fields in launch_windows
                if len(fields)==1 and fields[0] in candidates)
    return sorted(candidates),matches

def audit(path):
    from androguard.core.dex import DEX
    src=Path(path)
    need(src.is_file() and not src.is_symlink(),"ORIGINAL_FILE")
    need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,
         "ORIGINAL_SIGNED_SHA")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None,"ORIGINAL_ZIP_CRC")
        dexnames=sorted(n for n in z.namelist()
                        if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(dexnames==["classes.dex","classes2.dex"],"TWO_ORIGINAL_DEX")
        dexes=[(n,DEX(z.read(n))) for n in dexnames]
    fields,events,launches,scanned=extract_events(dexes)
    need(len(launches)==4,"MAIN_FOUR_ORIGINAL_LAUNCHES")
    counts=Counter((kind,label,detail)
                   for _,kind,_,_,_,label,detail in events)
    perm_fields,near_matches=field_hints(events,launches)
    print("P216_SIGNED_V138_ORIGINAL_SHA_PINNED=PASS")
    print("P216_MAIN_ACTIVITY_LAUNCHER_TYPED_FIELD_COUNT="+str(len(fields)))
    print("P216_ORIGINAL_CODE_METHODS_SCANNED="+str(scanned))
    print("P216_ORIGINAL_ACTIVITY_RESULT_EVENT_COUNT="+str(len(events)))
    for kind in ("MAIN_ACTIVITY","MAIN_NESTED","OTHER_ORIGINAL_APP","BUNDLED_LIBRARY"):
        for label in ("PERMISSION_CONTRACT_NEW","OTHER_CONTRACT_NEW",
                      "ACTIVITY_RESULT_REGISTER","GENERIC_LAUNCH"):
            n=sum(count for (x,l,_),count in counts.items() if x==kind and l==label)
            print("P216_"+kind+"_"+label+"_COUNT="+str(n))
        for subtype in ("REQUEST_ONE","REQUEST_MULTIPLE"):
            print("P216_"+kind+"_CONTRACT_NEW_"+subtype+"_COUNT="+
                  str(counts[(kind,"PERMISSION_CONTRACT_NEW",subtype)]))
    for i,(pc,near) in enumerate(launches,1):
        print("P216_MAIN_GENERIC_LAUNCH_"+str(i)+"_BYTE_PC="+str(pc))
        print("P216_MAIN_GENERIC_LAUNCH_"+str(i)+"_NEARBY_TYPED_FIELD_COUNT="+
              str(len(near)))
        print("P216_MAIN_GENERIC_LAUNCH_"+str(i)+"_FIELD_HINT="+
              (str(near[0]) if len(near)==1 else "AMBIGUOUS_OR_ABSENT"))
    print("P216_MAIN_PERMISSION_CONTRACT_REGISTER_SAME_METHOD_FIELD_HINT_COUNT="+
          str(len(perm_fields)))
    print("P216_MAIN_LAUNCH_MATCHES_NEARBY_REGISTER_FIELD_HINT="+
          str(near_matches))
    print("P216_FIELD_PROXIMITY_IS_NOT_DALVIK_REGISTER_DATAFLOW=YES")
    print("P216_ACTIVITY_RESULT_LAUNCH_IS_NOT_AUTOMATIC_PERMISSION_PROOF=YES")
    print("P216_PERMISSIONS_LITERALS_AND_RAW_FIELD_NAMES_EXPOSED=NO")
    print("P216_PERMISSION_CONTROLLER_REQUEST_ORIGIN=NOT_ATTESTED")
    print("P216_PC3912_RUNTIME_CAUSE=NOT_ATTESTED")
    print("P216_SIGNED_ORIGINAL_USER_DATA_MODIFIED=NO")
    print("P216_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P216_SIGNED_ACTIVITY_RESULT_STATIC_AUDIT=PASS")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("signed_original_v138")
    a=ap.parse_args()
    try:audit(a.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P216_ORIGINAL_CONTRACT_DENY_UNEXPECTED",file=sys.stderr);sys.exit(2)

if __name__=="__main__":main()
