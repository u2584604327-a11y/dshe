#!/usr/bin/env python3
"""P127: stage only SHA-pinned ORIGINAL v138 ARM64 Node and needed libraries.

Source-only disposable runner input for an offline Google APIs emulator.
Not the installed user APK, not original EngineManager, not a tool broker.
"""
import argparse, hashlib, io, pathlib, re, zipfile
from p123_original_node_elf_isolation_preflight import (
    audit, ASSET, BOOTSTRAP, ELF_SHA, ELF_SIZE
)

MAX_FILE=65*1024*1024
MAX_TOTAL=190*1024*1024
LIB_NAME=re.compile(r"[A-Za-z0-9_+.-]{1,128}\Z")

def require(ok, code):
    if not ok:raise ValueError(code)

def stage(original, root):
    audit(original)  # pins signed-v138, both resource archives, ELF and deps
    require(not root.exists(), "P127_STAGE_ALREADY_EXISTS")
    root.mkdir(parents=True, mode=0o700)
    with zipfile.ZipFile(original) as apk:
        with zipfile.ZipFile(io.BytesIO(apk.read(ASSET))) as node_pack:
            node=node_pack.read("bin/node")
            node_names=node_pack.namelist()
            node_links=node_pack.read("LINKS.txt").decode()
            node_libs={name.removeprefix("lib/"):node_pack.read(name)
                       for name in node_names
                       if name.startswith("lib/") and not name.endswith("/")}
        with zipfile.ZipFile(io.BytesIO(apk.read(BOOTSTRAP))) as base:
            base_names=base.namelist()
            bootstrap_links=base.read("SYMLINKS.txt").decode()
            base_libs={name.removeprefix("lib/"):base.read(name)
                       for name in base_names
                       if name.startswith("lib/") and not name.endswith("/")}
    require(len(node)==ELF_SIZE and hashlib.sha256(node).hexdigest()==ELF_SHA,
            "P127_EXACT_NODE_ELF_PREIMAGE_DRIFT")
    require(len(node_libs)>0 and len(base_libs)>0,"P127_NO_LIBRARY_CONTENT")
    bin_dir=root/"bin"
    lib_dir=root/"lib"
    bin_dir.mkdir()
    lib_dir.mkdir()
    executable=bin_dir/"node"
    executable.write_bytes(node)
    executable.chmod(0o700)
    combined=dict(base_libs)
    for name,value in node_libs.items():
        if name in combined and combined[name]!=value:
            raise ValueError("P127_CONFLICTING_LIBRARY_BYTES")
        combined[name]=value
    total=len(node)
    for name,data in sorted(combined.items()):
        require(LIB_NAME.fullmatch(name) is not None,"P127_BAD_LIBRARY_NAME")
        require(0<len(data)<=MAX_FILE,"P127_LIBRARY_SIZE_NOT_BOUNDED")
        total+=len(data)
        require(total<=MAX_TOTAL,"P127_TOO_MUCH_LIBRARY_DATA")
        (lib_dir/name).write_bytes(data)
    links={}
    for line in node_links.splitlines():
        pair=line.split()
        require(len(pair)==2 and pair[0].startswith("lib/") and
                "/" not in pair[1],"P127_BAD_NODE_LINK")
        links[pair[0].removeprefix("lib/")]=pair[1]
    for line in bootstrap_links.splitlines():
        if "←" not in line:continue
        target, source=line.split("←",1)
        if source.startswith("./lib/") and "/" not in target:
            alias=source.removeprefix("./lib/")
            if alias in links and links[alias]!=target:
                raise ValueError("P127_CONFLICTING_LIBRARY_LINK")
            links[alias]=target
    created=0
    for alias,target in sorted(links.items()):
        require(LIB_NAME.fullmatch(alias) is not None and
                LIB_NAME.fullmatch(target) is not None,
                "P127_UNSAFE_LINK_TARGET")
        if alias in combined:
            require(alias==target or combined[alias]==combined.get(target),
                    "P127_SYMLINK_WOULD_REPLACE_REAL_LIBRARY")
            continue
        if target in combined:
            (lib_dir/alias).symlink_to(target)
            created+=1
    for needed in ("libssl.so.3","libcrypto.so.3","libc++_shared.so",
                   "libz.so.1","libcares.so","libsqlite3.so",
                   "libicui18n.so.78","libicuuc.so.78","libffi.so"):
        require((lib_dir/needed).exists(),"P127_MISSING_PINNED_NEEDED_"+needed)
    print("P127_ORIGINAL_NODE_AND_BOOTSTRAP_EXACT_SHA=PASS")
    print("P127_ARM64_NODE_LIBS_STAGED_READONLY_FOR_EMULATOR=PASS")
    print("P127_STATIC_STAGED_LIBRARIES="+str(len(combined)))
    print("P127_STATIC_STAGED_SYMLINKS="+str(created))
    print("P127_ISOLATED_NODE_EXECUTION=NOT_TESTED")
    print("P127_NATIVE_TOOLS=DENY_ALL")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("signed_v138",type=pathlib.Path)
    parser.add_argument("stage_dir",type=pathlib.Path)
    opts=parser.parse_args()
    stage(opts.signed_v138,opts.stage_dir)

if __name__=="__main__":main()
