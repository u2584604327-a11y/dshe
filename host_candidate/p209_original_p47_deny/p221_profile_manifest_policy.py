#!/usr/bin/env python3
"""P221: fail-closed signed-v138 and disposable APK profiler eligibility audit.

Only reads SHA-pinned original and offline disposable APK manifests. Never
enables debug/profileable flags, changes ZIP/DEX, or accesses live app data.
Prints fixed enums; no raw manifest, permission or asset string is exposed.
"""
import argparse
import hashlib
from pathlib import Path
import sys
from audit_signed_node_bootstrap import SIGNED_SHA, Denied, need

ANDROID="{http://schemas.android.com/apk/res/android}"
PACKAGE="com.dsh.android"
MAX_APK=256*1024*1024

def android_bool(raw,default):
    if raw is None:return default
    if raw in ("true","1"):return True
    if raw in ("false","0"):return False
    raise Denied("P221_MANIFEST_BOOLEAN_NOT_LITERAL")

def manifest_policy(root):
    need(root is not None and root.tag=="manifest",
         "P221_MANIFEST_ROOT")
    need(root.get("package")==PACKAGE,"P221_PACKAGE_DRIFT")
    applications=root.findall("application")
    need(len(applications)==1,"P221_ONE_APPLICATION")
    app=applications[0]
    debug=android_bool(app.get(ANDROID+"debuggable"),False)
    nodes=app.findall("profileable")
    need(len(nodes)<=1,"P221_ONE_PROFILEABLE")
    profile=nodes[0] if nodes else None
    shell=android_bool(profile.get(ANDROID+"shell"),False) if profile is not None else False
    enabled=(android_bool(profile.get(ANDROID+"enabled"),True)
             if profile is not None else True)
    # Explicit profileable enabled=false prohibits profiling, including debug.
    permitted=enabled and (debug or shell)
    return {
        "debuggable":debug,
        "shell_profileable":enabled and shell,
        "profile_enabled":enabled,
        "eligible":permitted,
        "declared":profile is not None,
    }

def _apk_xml(path,original):
    from androguard.core.apk import APK
    src=Path(path)
    need(src.is_file() and not src.is_symlink() and
         32<=src.stat().st_size<=MAX_APK,"P221_BOUNDED_APK_REQUIRED")
    if original:
        need(hashlib.sha256(src.read_bytes()).hexdigest()==SIGNED_SHA,
             "P221_SIGNED_ORIGINAL_SHA")
    # No decoded manifest, package strings, permissions or file contents logged.
    return APK(str(src)).get_android_manifest_xml()

def audit(signed_original,disposable):
    source=manifest_policy(_apk_xml(signed_original,True))
    derived=manifest_policy(_apk_xml(disposable,False))
    for label,flags in (("ORIGINAL",source),("DISPOSABLE",derived)):
        for key,out in (("DEBUGGABLE","debuggable"),
                        ("SHELL_PROFILEABLE","shell_profileable"),
                        ("PROFILE_ENABLED","profile_enabled"),
                        ("PROFILE_DECLARED","declared"),
                        ("SHELL_PROFILE_ALLOWED","eligible")):
            print("P221_"+label+"_"+key+"="+
                  ("YES" if flags[out] else "NO"))
    print("P221_ORIGINAL_AND_DISPOSABLE_PROFILE_POLICY_DIFFER="+
          ("YES" if source!=derived else "NO"))
    print("P221_METHOD_TRACE_EMPTY_FILE_CAUSE=NOT_PROVEN")
    print("P221_MANIFEST_PROFILER_ELIGIBILITY_IS_NOT_RUNTIME_TRACE=YES")
    print("P221_NO_ORIGINAL_APK_OR_DEVICE_SECURITY_MUTATION=YES")
    print("P221_V139=STRUCTURAL_BLOCKED")
    print("P221_SIGNED_AND_DISPOSABLE_MANIFEST_POLICY_AUDIT=PASS")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("signed_original_v138")
    parser.add_argument("disposable_offline_apk")
    x=parser.parse_args()
    try:
        audit(x.signed_original_v138,x.disposable_offline_apk)
    except Denied as err:
        print(str(err),file=sys.stderr)
        return 2
    except Exception:
        print("P221_UNEXPECTED_MANIFEST_AUDIT_DENY",file=sys.stderr)
        return 2
    return 0

if __name__=="__main__":sys.exit(main())
