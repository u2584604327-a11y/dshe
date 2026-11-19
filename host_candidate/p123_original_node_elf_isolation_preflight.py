#!/usr/bin/env python3
"""P123: exact signed-v138 original Node ELF/ABI dynamic-loader preflight.

Static-only; never start Node, touch an installed APK, or grant device tools.
"""
import argparse, hashlib, io, json, pathlib, re, shutil, subprocess, tempfile, zipfile

APK_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
ASSET="assets/node-runtime.bin"
BOOTSTRAP="assets/bootstrap-aarch64.zip"
BOOTSTRAP_SHA="b3739c14a2eb7421243b908e2fe2b9e54cbdf8477d210d09e8ac4452d864cad9"
BOOTSTRAP_BYTES=24230081
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
        require(apk.namelist().count(ASSET)==1 and apk.namelist().count(BOOTSTRAP)==1,
                "P123_RUNTIME_OR_BOOTSTRAP_NOT_UNIQUE")
        archived=apk.read(ASSET)
        bootstrap=apk.read(BOOTSTRAP)
    require(len(bootstrap)==BOOTSTRAP_BYTES and sha(bootstrap)==BOOTSTRAP_SHA,
            "P123_BOOTSTRAP_AARCH64_ASSET_HASH_DRIFT")
    with zipfile.ZipFile(io.BytesIO(bootstrap)) as foundation:
        entries=foundation.namelist()
        require(entries.count("SYMLINKS.txt")==1 and len(entries)==len(set(entries)),
                "P123_BOOTSTRAP_ARCHIVE_STRUCTURE_CHANGED")
        require(all(".." not in pathlib.PurePosixPath(x).parts for x in entries),
                "P123_BOOTSTRAP_ARCHIVE_TRAVERSAL")
        bootstrap_library_files=sorted(x.removeprefix("lib/") for x in entries
                 if x.startswith("lib/") and not x.endswith("/"))
        bootstrap_links=foundation.read("SYMLINKS.txt").decode("utf-8")
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
    bootstrap_mapping={}
    for item in bootstrap_links.splitlines():
        if "←" not in item:continue
        target,source=item.split("←",1)
        if source.startswith("./lib/") and "/" not in target:
            bootstrap_mapping[source.removeprefix("./lib/")]=target
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
    combined=set(library_files)|set(bootstrap_library_files)
    covered=sorted(x for x in needed if x in combined or
                   (x in mappings and mappings[x] in combined) or
                   (x in bootstrap_mapping and bootstrap_mapping[x] in combined))
    os_baseline=sorted(x for x in needed if x not in covered)
    require(len(covered)==9 and os_baseline==["libc.so","libdl.so","libm.so"],
            "P123_COMBINED_ARM64_RUNTIME_LIBRARY_CLOSURE_DRIFT")
    changed=bytearray(elf)
    changed[4096]^=1
    require(len(changed)==ELF_SIZE and sha(changed)!=ELF_SHA,
            "P123_SAME_SIZE_TAMPER_NEGATIVE_FAILED")
    return {
      "source":{"exact_signed_v138_apk_sha256":APK_SHA,
                "node_runtime_zip_sha256":ASSET_SHA,
                "node_runtime_zip_bytes":RUNTIME_SIZE,
                "bootstrap_aarch64_zip_sha256":BOOTSTRAP_SHA,
                "bootstrap_aarch64_zip_bytes":BOOTSTRAP_BYTES,
                "node_elf_sha256":ELF_SHA,"node_elf_bytes":ELF_SIZE},
      "actual_elf":{"architecture":"AArch64","interpreter":interpreters[0],
                    "runpath":paths[0],"dt_needed":needed,
                    "runtime_lib_files":library_files,
                    "resolved_by_zip_link_metadata":resolved_links,
                    "unresolved_in_exact_runtime_archive":unresolved,
                    "bootstrap_library_files":bootstrap_library_files,
                    "combined_archives_provide":covered,
                    "android_base_libraries_needed":os_baseline},
      "gates":{"exact_source":"PASS","same_length_tamper":"REJECTED",
               "two_signed_v138_arm64_asset_archives":"PASS_SHA_PINNED",
               "direct_node_dt_needed_archive_closure":"9_OF_12_PLUS_3_ANDROID_BASE_LIBRARIES_STATIC",
               "node_start_in_x86_64_emulator":"NOT_TESTED_NATIVE_BRIDGE_UNKNOWN",
               "isolated_android_node_exec":"NOT_TESTED",
               "isolated_uid_library_resolution":"NOT_TESTED",
               "termux_private_runpath_access":"NOT_PROVEN",
               "original_core_plugin_os_separation":"NOT_WIRED",
               "p109_sensitive_tools":"DENY_ALL",
               "v139_release":"BLOCKED"},
      "scope":"Static inspection of original Node runtime ZIP plus the separate exact signed-v138 bootstrap-aarch64 ZIP and their link metadata. Nine ELF DT_NEEDED names resolve to files in the combined archives and libc/libm/libdl are Android baseline; no isolated UID extraction, runtime linker resolution or Node execution proven."
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
    print("P123_COMBINED_NODE_AND_BOOTSTRAP_LIBRARY_CLOSURE=PASS_STATIC")
    print("P123_TAMPER_NEGATIVE=PASS")
    print("P123_ISOLATED_NODE_EXEC=NOT_PROVEN")
    print("P123_NATIVE_TOOLS=DENY_ALL")

if __name__=="__main__":
    main()
