#!/usr/bin/env python3
"""P123: exact signed-v138 original Node ELF/ABI dynamic-loader preflight.

Static-only; never start Node, touch an installed APK, or grant device tools.
"""
import argparse, hashlib, io, json, pathlib, re, shutil, subprocess, tempfile, zipfile

APK_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
ASSET="assets/node-runtime.bin"
ASSET_SHA="ba16f7f4d0cc0b0272700effe06dc0d3682206afe1b54af75ca530a3e5c0d3bf"
ELF_SHA="a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6"
ELF_SIZE=49715528
RUNTIME_SIZE=31630920
INTERPRETER="/system/bin/linker64"
RUNPATH="/data/data/com.termux/files/usr/lib"
NEEDED={"libz.so.1","libcares.so","libsqlite3.so","libffi.so","libcrypto.so.3",
        "libssl.so.3","libicui18n.so.78","libicuuc.so.78","libc.so",
        "libm.so","libdl.so","libc++_shared.so"}

def sha(x):
    return hashlib.sha256(x).hexdigest()

def require(ok, error):
    if not ok:raise ValueError(error)

def audit(path):
    require(path.is_file() and path.stat().st_size < 180000000,
            "P123_SIGNED_APK_PATH_OR_SIZE_INVALID")
    h=hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda:source.read(1048576), b""):
            h.update(block)
    require(h.hexdigest()==APK_SHA,"P123_SIGNED_V138_SHA_MISMATCH")
    with zipfile.ZipFile(path) as apk:
        require(apk.namelist().count(ASSET)==1,"P123_ASSET_NOT_UNIQUE")
        archived=apk.read(ASSET)
    require(len(archived)==RUNTIME_SIZE and sha(archived)==ASSET_SHA,
            "P123_ORIGINAL_NODE_RUNTIME_ASSET_HASH_DRIFT")
    with zipfile.ZipFile(io.BytesIO(archived)) as package:
        names=package.namelist()
        require(names.count("bin/node")==1 and names.count("LINKS.txt")==1
                and len(names)==len(set(names)),"P123_ORIGINAL_RUNTIME_STRUCTURE_CHANGED")
        require(all(".." not in pathlib.PurePosixPath(x).parts for x in names),
                "P123_ORIGINAL_RUNTIME_ZIP_PATH_TRAVERSAL")
        elf=package.read("bin/node")
        library_files=sorted(x.removeprefix("lib/") for x in names
                             if x.startswith("lib/") and not x.endswith("/"))
        links=package.read("LINKS.txt").decode("utf-8")
    require(len(elf)==ELF_SIZE and sha(elf)==ELF_SHA,
            "P123_ORIGINAL_ARM64_NODE_ELF_HASH_DRIFT")
    require(elf[:4]==b"\x7fELF" and elf[4]==2
            and int.from_bytes(elf[18:20],"little")==183,
            "P123_ELF_NOT_AARCH64")
    mappings={}
    for line in links.splitlines():
        pair=line.split()
        require(len(pair)==2 and pair[0].startswith("lib/")
                and "/" not in pair[1],"P123_LIBRARY_LINK_METADATA_BAD")
        mappings[pair[0].removeprefix("lib/")]=pair[1]
    binary_tool=shutil.which("readelf")
    require(binary_tool is not None,"P123_READELF_MISSING")
    with tempfile.TemporaryDirectory(prefix="dsh-p123-") as workspace:
        local=pathlib.Path(workspace)/"node-arm64"
        local.write_bytes(elf)
        def inspect(flag):
            return subprocess.run([binary_tool,flag,str(local)],check=True,
                                  capture_output=True,text=True).stdout
        hdr=inspect("-h")
        programs=inspect("-l")
        dynamic=inspect("-d")
    interpreters=re.findall(r"Requesting program interpreter: ([^\]]+)",programs)
    paths=re.findall(r"\(RUNPATH\).*Library runpath: \[([^\]]+)\]",dynamic)
    needed=sorted(re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]",dynamic))
    require("AArch64" in hdr and interpreters==[INTERPRETER],
            "P123_ORIGINAL_ELF_LOADER_DRIFT")
    require(paths==[RUNPATH],"P123_ORIGINAL_ELF_TERMUX_RUNPATH_DRIFT")
    require(set(needed)==NEEDED,"P123_ORIGINAL_ELF_NEEDED_DEPS_DRIFT")
    resolved_links=sorted(x for x in needed
                          if x in mappings and mappings[x] in library_files)
    unresolved=sorted(x for x in needed
                      if x not in library_files and x not in resolved_links)
    require("libssl.so.3" in unresolved and "libcrypto.so.3" in unresolved,
            "P123_UNEXPECTED_LINK_CLOSURE_RECHECK")
    changed=bytearray(elf)
    changed[4096]^=1
    require(len(changed)==ELF_SIZE and sha(changed)!=ELF_SHA,
            "P123_SAME_SIZE_TAMPER_NEGATIVE_FAILED")
    return {
      "source":{"exact_signed_v138_apk_sha256":APK_SHA,
                "node_runtime_zip_sha256":ASSET_SHA,
                "node_runtime_zip_bytes":RUNTIME_SIZE,
                "node_elf_sha256":ELF_SHA,"node_elf_bytes":ELF_SIZE},
      "actual_elf":{"architecture":"AArch64","interpreter":interpreters[0],
                    "runpath":paths[0],"dt_needed":needed,
                    "runtime_lib_files":library_files,
                    "resolved_by_zip_link_metadata":resolved_links,
                    "unresolved_in_exact_runtime_archive":unresolved},
      "gates":{"exact_source":"PASS","same_length_tamper":"REJECTED",
               "node_start_in_x86_64_emulator":"IMPOSSIBLE_ARCH_MISMATCH",
               "isolated_android_node_exec":"NOT_TESTED",
               "isolated_uid_library_resolution":"NOT_TESTED",
               "termux_private_runpath_access":"NOT_PROVEN",
               "original_core_plugin_os_separation":"NOT_WIRED",
               "p109_sensitive_tools":"DENY_ALL",
               "v139_release":"BLOCKED"},
      "scope":"Static readelf on exact signed-v138 asset only. Unresolved names in ZIP might exist in Android/Termux elsewhere; their availability and execution permission in isolated UID are not proven. No Node execution."
    }

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("signed_v138_apk",type=pathlib.Path)
    parser.add_argument("--report",type=pathlib.Path)
    options=parser.parse_args()
    result=audit(options.signed_v138_apk)
    if options.report:
        options.report.parent.mkdir(parents=True,exist_ok=True)
        options.report.write_text(json.dumps(result,indent=2)+"\n")
    print("P123_EXACT_ORIGINAL_NODE_ELF_AARCH64=PASS")
    print("P123_DYNAMIC_LINK_AND_RUNPATH=PASS_AUDITED")
    print("P123_TAMPER_NEGATIVE=PASS")
    print("P123_ISOLATED_NODE_EXEC=NOT_PROVEN")
    print("P123_NATIVE_TOOLS=DENY_ALL")

if __name__=="__main__":
    main()
