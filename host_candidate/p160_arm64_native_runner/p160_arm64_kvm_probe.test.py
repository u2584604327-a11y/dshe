#!/usr/bin/env python3
"""P160 mocked KVM API tests; zero real host /dev/kvm calls."""
import importlib.util
import os
import stat
from types import SimpleNamespace
from pathlib import Path
spec=importlib.util.spec_from_file_location(
    "p160",Path(__file__).with_name("p160_arm64_kvm_probe.py"))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
calls=[]

def char(path):
    assert path=="/dev/kvm"
    return SimpleNamespace(st_mode=stat.S_IFCHR | 0o600)
def good_open(path,flags):
    assert flags & os.O_RDWR
    return 81
def good_ioctl(fd,request,arg):
    calls.append((fd,request))
    if request==module.API_VERSION:return 12
    if request==module.CREATE_VM:return 82
    raise AssertionError("UNRECOGNIZED_KVM_IOCTL")
def closed(fd):
    calls.append(("close",fd))
assert module.classify(stat_fn=char,open_fn=good_open,
                       ioctl_fn=good_ioctl,close_fn=closed)==\
       "KVM_VM_CREATE_PASS_NO_GUEST"
assert ("close",81) in calls and ("close",82) in calls
assert module.classify(stat_fn=lambda x: (_ for _ in ()).throw(
    FileNotFoundError()))=="NO_KVM_CHAR_DEVICE"
assert module.classify(stat_fn=lambda x: SimpleNamespace(
    st_mode=stat.S_IFREG))=="NOT_A_CHAR_DEVICE"
assert module.classify(stat_fn=char,open_fn=lambda *x: (_ for _ in ()).throw(
    PermissionError()))=="KVM_OPEN_PERMISSION_DENIED"
assert module.classify(stat_fn=char,open_fn=good_open,
    ioctl_fn=lambda f,r,arg: 7,
    close_fn=closed)=="KVM_API_VERSION_UNEXPECTED"
assert module.classify(stat_fn=char,open_fn=good_open,
    ioctl_fn=lambda f,r,arg: (_ for _ in ()).throw(
        OSError(22,"Invalid argument")),
    close_fn=closed)=="KVM_IOCTL_DENIED_OR_UNSUPPORTED"
print("P160_KVM_IOCTL_MOCK_POSITIVES_NEGATIVES=PASS")
print("P160_MOCK_REAL_VM_OR_ANDROID_USED=NO")
