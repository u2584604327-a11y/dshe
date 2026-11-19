#!/usr/bin/env python3
"""P128: transitive DT_NEEDED graph of exact signed-v138 original ARM64 Node.

Offline static provenance only: no Android, no Node execution and no tool rights.
"""
import argparse, json, pathlib, re, shutil, subprocess, tempfile
from p127_google_apis_nativebridge_original_node_stage import stage
from p123_original_node_elf_isolation_preflight import NEEDED

# Named Android Bionic/NDK platform deps (availability in an isolated namespace
# is NOT proven by static naming).
ANDROID_SYSTEM_CANDIDATES={
    "libc.so","libm.so","libdl.so","liblog.so","libandroid.so",
    "libz.so","libstdc++.so","libEGL.so","libGLESv1_CM.so",
    "libGLESv2.so","libGLESv3.so","libvulkan.so","libjnigraphics.so",
    "libOpenSLES.so","libaaudio.so"
}
LIB_RE=re.compile(r"[A-Za-z0-9_+.-]{1,128}\Z")
NEEDED_RE=re.compile(r"\(NEEDED\).*Shared library: \[([^\]]+)\]")
MAX_VISITS=160

def dependencies(path, readelf):
    with path.open("rb") as fd:
        head=fd.read(20)
    if len(head)<20 or head[:4]!=b"\x7fELF" or head[4]!=2:
        return None, "NOT_ELF64"
    if int.from_bytes(head[18:20],"little")!=183:
        return None, "NOT_AARCH64"
    out=subprocess.run([readelf,"-d",str(path)],capture_output=True,
                       text=True,timeout=12)
    if out.returncode!=0:
        return None, "READELF_INVALID_DYNAMIC_SECTION"
    names=NEEDED_RE.findall(out.stdout)
    if not all(LIB_RE.fullmatch(v) is not None for v in names):
        return None,"UNSAFE_DEPENDENCY_NAME"
    return sorted(set(names)),None

def audit_full_tree(apk):
    readelf=shutil.which("readelf")
    if not readelf:raise ValueError("P128_READELF_NOT_FOUND")
    with tempfile.TemporaryDirectory(prefix="p128-original-node-") as folder:
        root=pathlib.Path(folder)/"assets"
        stage(apk,root)
        available={v.name:v for v in (root/"lib").iterdir()
                   if v.is_file() and LIB_RE.fullmatch(v.name)}
        pending=[("bin/node",k) for k in sorted(NEEDED)]
        visited=set()
        graph={}
        missing=set()
        assumed=set()
        invalid={}
        while pending:
            parent,name=pending.pop(0)
            if name in ANDROID_SYSTEM_CANDIDATES:
                assumed.add(name)
                continue
            if name not in available:
                missing.add(name)
                continue
            if name in visited:continue
            visited.add(name)
            if len(visited)>MAX_VISITS:
                raise ValueError("P128_TRANSITIVE_GRAPH_EXCEEDS_BOUND")
            needs,reason=dependencies(available[name],readelf)
            if reason:
                invalid[name]=reason
                continue
            graph[name]=needs
            pending.extend((name,needed) for needed in needs)
        result={
          "signed_original_source":"SHA_PINNED_P123_AND_P127",
          "source_elf":"a0d21a1589312919114b24a5cc520c30ab7f26f9985b3f0c643c153172ebd1e6",
          "direct_node_needed":sorted(NEEDED),
          "staged_flat_library_files":len(available),
          "transitive_elf_libraries_visited":len(visited),
          "transitive_dependencies":graph,
          "missing_in_pinned_runtime_and_bootstrap":sorted(missing),
          "not_64bit_aarch64_or_invalid":invalid,
          "android_platform_names_assumed_not_verified":sorted(assumed),
          "android_isolated_uid_dlopen_and_namespace":"NOT_TESTED",
          "original_arm64_node_version_runtime":"BLOCKED_PREVIOUS_P127",
          "sensitive_tool_access":"DENY_ALL",
          "formal_v139_release":"BLOCKED"
        }
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("signed_v138_apk",type=pathlib.Path)
    ap.add_argument("--report",type=pathlib.Path)
    opts=ap.parse_args()
    info=audit_full_tree(opts.signed_v138_apk)
    if opts.report:
        opts.report.parent.mkdir(parents=True,exist_ok=True)
        opts.report.write_text(json.dumps(info,indent=2,sort_keys=True)+"\n")
    print("P128_EXACT_ORIGINAL_ARM64_LOADER_TRANSITIVE_STATIC_AUDIT=PASS")
    print("P128_REACHABLE_AARCH64_LIBRARIES="+str(info["transitive_elf_libraries_visited"]))
    print("P128_STATIC_MISSING_TRANSITIVE_COUNT="+str(len(info["missing_in_pinned_runtime_and_bootstrap"])))
    print("P128_STATIC_MISSING_TRANSITIVE_NAMES="+",".join(info["missing_in_pinned_runtime_and_bootstrap"]))
    print("P128_STATIC_INVALID_ELF_COUNT="+str(len(info["not_64bit_aarch64_or_invalid"])))
    print("P128_ANDROID_LINKER_NAMESPACE=NOT_TESTED")
    print("P128_ORIGINAL_ISOLATED_NODE_EXEC=NOT_TESTED")
    print("P128_P109_TOOL_AUTHORITY=DENY_ALL")

if __name__=="__main__":main()
