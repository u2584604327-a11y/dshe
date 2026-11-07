#!/usr/bin/env python3
"""Read-only Apple Silicon Android guest prerequisites, never SDK install/boot."""
import argparse
import os
import pathlib
import platform
import re
import subprocess
import tempfile

APIS=(35,36)

def classify_accel(exit_code,output):
    s=output.lower()[:8192]
    if exit_code!=0:return "NOT_PROVEN"
    if not ("hypervisor.framework" in s or re.search(r"\bhvf\b",s)):
        return "NOT_PROVEN"
    if re.search(r"\b(?:not|no|unavailable|unsupported|can't|cannot)\b.{0,90}(?:usable|available|supported)",s):
        return "NOT_PROVEN"
    return "PASS" if "installed and usable" in s else "NOT_PROVEN"

def find_images(root):
    found={}
    for api in APIS:
        folder=root/"system-images"/("android-"+str(api))
        ok=False
        if folder.is_dir():
            for variant in sorted(folder.iterdir()):
                candidate=variant/"arm64-v8a"
                if (candidate.is_dir() and (candidate/"source.properties").is_file()
                    and any((candidate/name).is_file()
                            for name in ("system.img","system-qemu.img"))):
                    ok=True
        found[api]="PRESENT" if ok else "NOT_PREINSTALLED"
    return found

def check(root):
    host=platform.system()=="Darwin" and platform.machine().lower() in ("arm64","aarch64")
    images=find_images(root)
    binary=root/"emulator"/"emulator"
    sdk=(root/"platform-tools"/"adb").is_file() and binary.is_file()
    accel="NOT_PROVEN"
    if host and binary.is_file():
        try:
            result=subprocess.run([str(binary),"-accel-check"],capture_output=True,
                                  text=True,errors="replace",timeout=10,check=False)
            accel=classify_accel(result.returncode,result.stdout+"\n"+result.stderr)
        except (OSError,subprocess.TimeoutExpired):
            pass
    print("MAC_ARM64_HOST="+("PASS" if host else "NOT_PROVEN"))
    print("MAC_ANDROID_SDK_TOOLS="+("PRESENT" if sdk else "NOT_PREINSTALLED"))
    print("MAC_ANDROID_HVF="+accel)
    for api in APIS:
        print("MAC_ANDROID_API_"+str(api)+"_ARM64_IMAGE="+images[api])
        qualified=host and sdk and accel=="PASS" and images[api]=="PRESENT"
        print("MAC_ANDROID_"+str(api)+"_ARM64_GUEST_PREREQUISITES="+
              ("PRESENT" if qualified else "BLOCKED"))
    print("MAC_ANDROID_GUEST_BOOTED=NO")
    print("MAC_ORIGINAL_NODE_OR_ENGINEMANAGER_STARTED=NO")
    print("MAC_SDK_INSTALL_OR_LICENSE_ACCEPTANCE=NOT_ATTEMPTED")
    print("MAC_FIXED_SIGNED_V139=BLOCKED")

def selftest():
    assert classify_accel(0,"accel: 0\nHypervisor.Framework is installed and usable")=="PASS"
    assert classify_accel(1,"HVF is installed and usable")=="NOT_PROVEN"
    assert classify_accel(0,"WHPX is installed and usable")=="NOT_PROVEN"
    assert classify_accel(0,"Hypervisor.Framework is not available")=="NOT_PROVEN"
    assert classify_accel(0,"Hypervisor.Framework is installed but not usable")=="NOT_PROVEN"
    with tempfile.TemporaryDirectory() as tmp:
        p=pathlib.Path(tmp)
        assert find_images(p)=={35:"NOT_PREINSTALLED",36:"NOT_PREINSTALLED"}
        candidate=p/"system-images"/"android-35"/"google_apis"/"arm64-v8a"
        candidate.mkdir(parents=True)
        (candidate/"source.properties").write_text("Pkg.Revision=1\n")
        assert find_images(p)[35]=="NOT_PREINSTALLED"
        (candidate/"system.img").write_bytes(b"synthetic")
        assert find_images(p)[35]=="PRESENT"
        assert find_images(p)[36]=="NOT_PREINSTALLED"
        x86=p/"system-images"/"android-36"/"google_apis"/"x86_64"
        x86.mkdir(parents=True)
        (x86/"source.properties").write_text("Pkg.Revision=1\n")
        (x86/"system.img").write_bytes(b"synthetic")
        assert find_images(p)[36]=="NOT_PREINSTALLED"
    print("MAC_ARM64_PREREQ_SYNTHETIC_NEGATIVES=PASS")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--selftest",action="store_true")
    p.add_argument("--inspect",action="store_true")
    args=p.parse_args()
    if args.selftest:selftest()
    elif args.inspect:
        root=os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") or ""
        check(pathlib.Path(root) if root else pathlib.Path("/nonexistent-sdk"))
    else:p.error("--selftest or --inspect required")
