#!/usr/bin/env python3
"""P215: pinned signed-v138 permission declaration + true invoke-owner audit.

Read only original signed APK and two DEX files. Manifest uses-permission
declarations are not runtime request events. A class-name hint from the
PermissionController cannot establish which original code requested anything.
No raw permission identifiers, manifest content, permission string operands,
intent extras, user data, call arguments or original APK contents are emitted.
"""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
import re
import sys
import zipfile

from audit_signed_node_bootstrap import SIGNED_SHA, need, Denied

DEX_NAMES=("classes.dex","classes2.dex")
APP="Lcom/dsh/android/"
SITE_BOUND=128
MANIFEST_BOUND=256
DIRECT_API_OWNERS=frozenset((
    "Landroid/app/Activity;",
    "Landroid/app/Fragment;",
    "Landroidx/core/app/ActivityCompat;",
    "Landroid/support/v4/app/ActivityCompat;",
    "Landroidx/fragment/app/Fragment;",
    "Landroid/support/v4/app/Fragment;",
))
LAUNCHER_OWNERS=frozenset((
    "Landroidx/activity/result/ActivityResultLauncher;",
    "Landroidx/activity/result/ActivityResultRegistry;",
))
INVOKE_OWNER=re.compile(
    r"(L[A-Za-z0-9_/$]{1,200};)->([A-Za-z0-9_$<>]{1,100})\(")
SOURCE_LABELS={
    "Lcom/dsh/android/MainActivity;":"MAIN_ACTIVITY",
    "Lcom/dsh/android/MainActivity$bootEngine$1;":"MAIN_BOOT_COROUTINE",
    "Lcom/dsh/android/EngineManager;":"ENGINE_MANAGER",
    "Lcom/dsh/android/EngineManager$start$2;":"ENGINE_START_COROUTINE",
    "Lcom/dsh/android/termux/TermuxBootstrap;":"TERMUX_BOOTSTRAP",
}
HOT_SOURCES=frozenset(SOURCE_LABELS)
KNOWN_NAMES=frozenset((
    "onCreate","bootEngine","start","invokeSuspend","onResume",
    "onRequestPermissionsResult","requestPermissions",
))
MANIFEST_TYPES=("NOTIFICATION","STORAGE_MEDIA","LOCATION",
                "CAMERA_MIC","NEARBY","OTHER")

def class_call(ins):
    """Use invoked callee owner, not descriptor mentions or field strings."""
    if not ins.get_name().startswith("invoke-"):
        return None
    match=INVOKE_OWNER.search(ins.get_output())
    return match.groups() if match else None

def permission_kind(owner,method):
    if method=="requestPermissions" and owner in DIRECT_API_OWNERS:
        return "DIRECT_REQUEST_API"
    if method=="launch" and owner in LAUNCHER_OWNERS:
        # Generic launch is NOT itself proof of permission request.
        return "GENERIC_ACTIVITY_RESULT_LAUNCH"
    if method=="registerForActivityResult" and owner.startswith((
            "Landroidx/activity/","Landroidx/fragment/")):
        return "GENERIC_ACTIVITY_RESULT_REGISTRATION"
    return None

def label_caller(owner):
    if owner in SOURCE_LABELS:return SOURCE_LABELS[owner]
    if owner.startswith(APP):return "ORIGINAL_APP_OTHER"
    return "BUNDLED_LIBRARY_OTHER"

def label_method(name):
    return name if name in KNOWN_NAMES else "OTHER_METHOD"

def inventory_sites(dexes):
    sites=[]
    counts=Counter()
    scanned=0
    for dex_name,dex in dexes:
        for cls in dex.get_classes():
            caller=cls.get_name()
            for meth in cls.get_methods():
                if meth.get_code() is None:continue
                scanned+=1
                need(scanned<=100000,"METHOD_SCAN_BOUND")
                for pc,ins in meth.get_instructions_idx():
                    target=class_call(ins)
                    if target is None:continue
                    owner,name=target
                    kind=permission_kind(owner,name)
                    if kind is None:continue
                    counts[(label_caller(caller),kind)]+=1
                    sites.append((dex_name,label_caller(caller),
                                  label_method(meth.get_name()),pc,kind))
                    need(len(sites)<=SITE_BOUND,"ORIGINAL_PERMISSION_SITE_BOUND")
    need(scanned>0,"SIGNED_METHODS_PRESENT")
    return sites,counts,scanned

def permission_group(permission):
    """Fixed category only. A declared permission is not an actual request."""
    if not isinstance(permission,str) or len(permission)>240:
        raise Denied("P215_INVALID_MANIFEST_PERMISSION_ENTRY")
    if permission=="android.permission.POST_NOTIFICATIONS":
        return "NOTIFICATION"
    if any(permission.startswith(prefix) for prefix in (
        "android.permission.READ_MEDIA_","android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE","android.permission.MANAGE_EXTERNAL_STORAGE")):
        return "STORAGE_MEDIA"
    if permission in (
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION"):
        return "LOCATION"
    if permission in ("android.permission.CAMERA",
                      "android.permission.RECORD_AUDIO"):
        return "CAMERA_MIC"
    if permission in ("android.permission.NEARBY_WIFI_DEVICES",
                      "android.permission.BLUETOOTH_CONNECT",
                      "android.permission.BLUETOOTH_SCAN",
                      "android.permission.BLUETOOTH_ADVERTISE"):
        return "NEARBY"
    return "OTHER"

def manifest_summary(perms):
    need(isinstance(perms,(list,tuple,set)) and len(perms)<=MANIFEST_BOUND,
         "MANIFEST_PERMISSION_COUNT_BOUND")
    result=Counter()
    for value in perms:
        result[permission_group(value)]+=1
    return result

def validate_apk(path):
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    src=Path(path)
    need(src.is_file() and not src.is_symlink(),"SIGNED_APK_FILE")
    need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,
         "SIGNED_ORIGINAL_SHA256")
    with zipfile.ZipFile(src) as z:
        need(z.testzip() is None,"SIGNED_ZIP_CRC")
        dexnames=sorted(n for n in z.namelist()
                        if re.fullmatch(r"classes(?:[2-9][0-9]*)?\.dex",n))
        need(dexnames==list(DEX_NAMES),"ORIGINAL_TWO_DEX_EXACT")
        dexes=[(n,DEX(z.read(n))) for n in dexnames]
    apk=APK(str(src))
    # APK.get_permissions is a declaration inventory, not a grant-state read.
    permissions=apk.get_permissions()
    need(isinstance(permissions,list),"MANIFEST_PERMISSION_LIST_REQUIRED")
    return dexes,permissions,apk.get_target_sdk_version()

def audit(path):
    dexes,permissions,target_sdk=validate_apk(path)
    groups=manifest_summary(permissions)
    sites,count,scanned=inventory_sites(dexes)
    print("P215_SIGNED_ORIGINAL_V138_SHA_PIN=PASS")
    print("P215_SIGNED_TWO_DEX_AND_ZIP_CRC=PASS")
    print("P215_MANIFEST_DECLARATION_COUNT="+str(len(permissions)))
    for category in MANIFEST_TYPES:
        print("P215_MANIFEST_DECLARATION_"+category+"_COUNT="+
              str(groups[category]))
    print("P215_MANIFEST_TARGET_SDK_CLASS="+
          ("MODERN_23_PLUS" if str(target_sdk).isdigit()
           and int(target_sdk)>=23 else "UNKNOWN_OR_LEGACY"))
    print("P215_ORIGINAL_DEX_METHODS_SCANNED="+str(scanned))
    print("P215_ORIGINAL_PERMISSION_RELATED_INVOKE_SITES="+str(len(sites)))
    for source in (*SOURCE_LABELS.values(),"ORIGINAL_APP_OTHER",
                   "BUNDLED_LIBRARY_OTHER"):
        print("P215_CALLER_"+source+"_DIRECT_REQUEST_API="+
              str(count[(source,"DIRECT_REQUEST_API")]))
        print("P215_CALLER_"+source+"_GENERIC_ACTIVITY_RESULT_LAUNCH="+
              str(count[(source,"GENERIC_ACTIVITY_RESULT_LAUNCH")]))
    for idx,(dex,caller,meth,pc,kind) in enumerate(sites[:48],1):
        print("P215_STATIC_CALLSITE_"+str(idx)+
              "=DEX:"+dex+",CALLER:"+caller+",METHOD:"+meth+
              ",BYTE_PC:"+str(pc)+",KIND:"+kind)
    print("P215_PERMISSION_LITERAL_STRINGS_EXPOSED=NO")
    print("P215_MANIFEST_DECLARATION_IS_NOT_RUNTIME_REQUEST=YES")
    print("P215_GENERIC_ACTIVITY_RESULT_LAUNCH_IS_NOT_PERMISSION_REQUEST=YES")
    print("P215_ORIGINAL_PERMISSION_REQUEST_RUNTIME_EXECUTED=NOT_ATTESTED")
    print("P215_PERMISSION_CONTROLLER_CAUSE_OF_PC3912=NOT_ATTESTED")
    print("P215_ORIGINAL_APK_AND_USER_DATA_MODIFIED=NO")
    print("P215_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P215_SIGNED_ORIGINAL_PERMISSION_STATIC_AUDIT=PASS")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("signed_original_v138")
    a=p.parse_args()
    try:audit(a.signed_original_v138)
    except Denied as e:
        print(str(e),file=sys.stderr);sys.exit(2)
    except Exception:
        print("P215_PERMISSION_AUDIT_DENY_UNEXPECTED",file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
