#!/usr/bin/env python3
"""P160: no-guest KVM API probe. No root, Android image, Node, VM vCPU or disk."""
import errno
import fcntl
import os
import stat

API_VERSION = 0xAE00
CREATE_VM = 0xAE01

def classify(path="/dev/kvm", stat_fn=os.stat, open_fn=os.open,
             ioctl_fn=fcntl.ioctl, close_fn=os.close):
    fd = None
    vm = None
    try:
        try:
            attrs=stat_fn(path)
        except FileNotFoundError:
            return "NO_KVM_CHAR_DEVICE"
        if not stat.S_ISCHR(attrs.st_mode):
            return "NOT_A_CHAR_DEVICE"
        try:
            fd=open_fn(path, os.O_RDWR | getattr(os,"O_CLOEXEC",0))
        except PermissionError:
            return "KVM_OPEN_PERMISSION_DENIED"
        except OSError:
            return "KVM_OPEN_FAILED"
        try:
            version=ioctl_fn(fd,API_VERSION,0)
            if version!=12:
                return "KVM_API_VERSION_UNEXPECTED"
            vm=ioctl_fn(fd,CREATE_VM,0)
            if not isinstance(vm,int) or vm<0:
                return "KVM_VM_CREATE_UNVERIFIED"
            return "KVM_VM_CREATE_PASS_NO_GUEST"
        except OSError:
            return "KVM_IOCTL_DENIED_OR_UNSUPPORTED"
    finally:
        if vm is not None and isinstance(vm,int) and vm>=0:
            close_fn(vm)
        if fd is not None:
            close_fn(fd)

if __name__=="__main__":
    print("P160_KVM="+classify())
    print("P160_GUEST_BOOTED=NO")
    print("P160_NODE_EXECUTED=NO")
