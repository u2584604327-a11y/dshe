#!/usr/bin/env python3
"""P55: bounded, read-only static startup/import audit of immutable DSH engine.

This NEVER executes original JS, loads native addons, emits module names or
source, writes extracted source, or grants private paths to a worker.
All reported imports are *literal/static hints*, not Node resolution proof.
"""
import argparse
import collections
import gzip
import hashlib
import io
import json
import pathlib
import posixpath
import re
import sys
import tarfile
import zipfile

# The P54 trusted scanner lives in its own sibling directory.
# Fixed local source import only; never network/module search from the archive.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "p54_engine_tree"))
from p54_immutable_tar_audit import exact_engine, safe_name

EXPECTED_TREE_SHA = "b2c7e52890351c4d1a3200c67ccb9be6154389a20da0b0b590d16676ce47b1e1"
ENGINE_ENTRY = "assets/engine.bin"
MAX_JS_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 512 * 1024
MAX_TOTAL_SCANNED = 384 * 1024 * 1024
MAX_LITERAL_IMPORTS = 350000
MAX_PACKAGE_METADATA = 12000
MAX_FIELD = 280
RE_LITERAL_IMPORT = re.compile(
    r'(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|\bimport\s+)'
    r'(["\x27])([^"\x27\r\n]{1,256})\1'
)
RE_DYN_REQUIRE = re.compile(
    r"\brequire\s*\(\s*(?![\"'])"
)
RE_DYN_IMPORT = re.compile(
    r"\bimport\s*\(\s*(?![\"'])"
)
RE_NODE_STRING = re.compile(r"[\"'][^\"'\r\n]{0,240}\.node[\"']")
RE_PLATFORM = re.compile(r"\bprocess\s*\.\s*(?:platform|arch)\b")
RE_NATIVE_LOADER = re.compile(
    r"\b(?:node-gyp-build|bindings|prebuildify|node-pre-gyp|"
    r"@napi-rs|process\.dlopen)\b", re.I
)
RE_LITERAL_DYNAMIC_NATIVE = re.compile(r"require\s*\(\s*[^\"'\s][^)]*\.node", re.I)


def require(ok, reason):
    if not ok:
        raise ValueError("P55_BLOCKED_" + reason)


def normalize_import(caller, spec):
    """Only a *lexical* relative resolution hint, not actual Node resolver."""
    if not isinstance(spec, str) or not spec.startswith(("./", "../")):
        return None
    if len(spec) > MAX_FIELD or "\\" in spec or "\x00" in spec:
        return None
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(caller), spec))
    if normalized.startswith("../") or normalized in (".", ".."):
        return None
    # Do not trust the original specifier for file opening; safe-name check.
    try:
        return safe_name(normalized)
    except ValueError:
        return None


def parse_package(raw):
    """Safe JSON only; duplicate keys invalidate a root package definition."""
    def no_duplicates(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError("P55_DUPLICATE_PACKAGE_JSON_KEY")
            result[k] = v
        return result
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def candidate_values(meta):
    """Bounded literal hints. Never interpret shell scripts as Node command."""
    vals = []
    for key in ("main", "module", "browser"):
        value = meta.get(key)
        if isinstance(value, str) and 0 < len(value) <= MAX_FIELD:
            vals.append((key, value))
    exports = meta.get("exports")
    if isinstance(exports, str) and 0 < len(exports) <= MAX_FIELD:
        vals.append(("exports", exports))
    elif isinstance(exports, dict):
        for key in (".", "default", "node", "import", "require"):
            v = exports.get(key)
            if isinstance(v, str) and 0 < len(v) <= MAX_FIELD:
                vals.append(("exports", v))
    bin_value = meta.get("bin")
    if isinstance(bin_value, str) and 0 < len(bin_value) <= MAX_FIELD:
        vals.append(("bin", bin_value))
    elif isinstance(bin_value, dict):
        for v in list(bin_value.values())[:10]:
            if isinstance(v, str) and 0 < len(v) <= MAX_FIELD:
                vals.append(("bin", v))
    return vals[:24]


def audit_tar(stream):
    present = set()
    addon_members = set()
    imports = []
    hinted_entries = []
    package_count = 0
    root_package_count = 0
    start_command_count = 0
    native_optional_dependency_count = 0
    counts = collections.Counter()
    total = 0
    for entry in stream:
        name = safe_name(entry.name)
        require(name not in present, "DUPLICATE_MEMBER")
        present.add(name)
        if entry.isdir():
            continue
        require(entry.isfile(), "NON_FILE")
        if name.endswith(".node"):
            addon_members.add(name)
        is_js = name.endswith((".js", ".mjs", ".cjs"))
        is_pkg = name.endswith("/package.json") or name == "package.json"
        if not (is_js or is_pkg):
            continue
        if is_pkg:
            package_count += 1
            require(package_count <= MAX_PACKAGE_METADATA, "PACKAGE_COUNT")
        limit = MAX_JS_BYTES if is_js else MAX_JSON_BYTES
        if entry.size > limit:
            counts["source_or_json_over_limit"] += 1
            continue
        total += entry.size
        require(total <= MAX_TOTAL_SCANNED, "SCAN_BYTES_LIMIT")
        inp = stream.extractfile(entry)
        require(inp is not None, "SOURCE_MEMBER_NOT_READABLE")
        # Small bounded buffer transiently in private CI; never print bytes.
        body = inp.read(limit + 1)
        require(len(body) == entry.size, "SHORT_SOURCE_READ")
        if is_pkg:
            meta = parse_package(body)
            if meta is None:
                counts["invalid_package_json"] += 1
                continue
            # Rootish: package tree depth <=2, not dependency packages.
            is_rootish = name.count("/") <= 2 and "node_modules" not in name.split("/")
            if is_rootish:
                root_package_count += 1
                for kind, value in candidate_values(meta):
                    resolved = normalize_import(name, value)
                    if resolved:
                        hinted_entries.append((kind, resolved))
                start = meta.get("scripts")
                if isinstance(start, dict) and isinstance(start.get("start"), str):
                    start_command_count += 1
                if meta.get("type") == "module":
                    counts["root_type_module"] += 1
            opt = meta.get("optionalDependencies")
            if isinstance(opt, dict):
                native_optional_dependency_count += len(opt)
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeError:
            counts["non_utf8_js"] += 1
            continue
        counts["js_sources_scanned"] += 1
        counts["conditional_platform_references"] += len(RE_PLATFORM.findall(text))
        counts["native_loader_pattern_hints"] += len(RE_NATIVE_LOADER.findall(text))
        counts["dynamic_require_unresolved_hints"] += len(RE_DYN_REQUIRE.findall(text))
        counts["dynamic_import_unresolved_hints"] += len(RE_DYN_IMPORT.findall(text))
        counts["native_addon_string_hints"] += len(RE_NODE_STRING.findall(text))
        counts["nonliteral_native_import_hints"] += len(RE_LITERAL_DYNAMIC_NATIVE.findall(text))
        for match in RE_LITERAL_IMPORT.finditer(text):
            spec = match.group(2)
            counts["literal_import_syntax_occurrences"] += 1
            require(counts["literal_import_syntax_occurrences"] <= MAX_LITERAL_IMPORTS,
                    "LITERAL_IMPORT_COUNT_CAP")
            if spec.startswith(("node:",)):
                counts["builtin_node_specifier_hints"] += 1
            elif spec.startswith(("./", "../")):
                relative = normalize_import(name, spec)
                if relative is None:
                    counts["unresolvable_or_unsafe_relative_literal"] += 1
                else:
                    imports.append((relative, spec.endswith(".node")))
            else:
                counts["package_or_builtin_import_hints"] += 1
    direct_native = 0
    direct_native_miss = 0
    relative_present = 0
    relative_missing = 0
    for target, is_node in imports:
        guesses = (target, target + ".js", target + ".mjs", target + ".cjs",
                   target + ".json", target + "/index.js",
                   target + "/index.mjs", target + "/index.cjs")
        if any(g in present for g in guesses):
            relative_present += 1
        else:
            relative_missing += 1
        if is_node:
            if target in addon_members: direct_native += 1
            else: direct_native_miss += 1
    entry_exists = 0
    for kind, target in hinted_entries:
        guesses = (target, target + ".js", target + ".mjs",
                   target + ".cjs", target + "/index.js")
        if any(g in present for g in guesses):
            entry_exists += 1
    counts.update({
        "archive_members_seen": len(present),
        "native_addon_members": len(addon_members),
        "package_json_members": package_count,
        "rootish_package_metadata": root_package_count,
        "root_start_command_present": start_command_count,
        "optional_dependency_metadata_keys": native_optional_dependency_count,
        "relative_literal_imports_detected": len(imports),
        "relative_literal_present_path_hint": relative_present,
        "relative_literal_missing_path_hint": relative_missing,
        "direct_static_native_addon_imports_present": direct_native,
        "direct_static_native_addon_imports_missing": direct_native_miss,
        "root_metadata_entrypoint_hints": len(hinted_entries),
        "root_metadata_entrypoint_literal_exists": entry_exists,
        "candidate_source_bytes_examined": total,
    })
    return counts


def run_exact_original(apk):
    # P54 full SHA/TAR audit is an independent prerequisite, not a shortcut.
    immutable = exact_engine(apk)
    require(immutable["tree_sha256"] == EXPECTED_TREE_SHA, "IMMUTABLE_TREE_DRIFT")
    require(immutable["members"] == 30411, "ARCHIVE_COUNT_DRIFT")
    with zipfile.ZipFile(apk) as z:
        encoded = z.read(ENGINE_ENTRY)
    with gzip.GzipFile(fileobj=io.BytesIO(encoded), mode="rb") as g:
        with tarfile.open(fileobj=g, mode="r|") as t:
            summary = audit_tar(t)
    require(summary["archive_members_seen"] == 30411,
            "SECOND_PASS_MEMBER_COUNT_CHANGED")
    require(summary["native_addon_members"] == 9, "ADDON_MEMBER_COUNT_CHANGED")
    return summary


def print_report(c):
    print("P55_EXACT_ORIGINAL_IMMUTABLE_TREE_ROOT=PASS")
    print("P55_STATIC_JS_IMPORT_SCAN=PASS_BOUNDED_HEURISTIC")
    keys = (
        "archive_members_seen", "js_sources_scanned",
        "source_or_json_over_limit", "candidate_source_bytes_examined",
        "package_json_members", "rootish_package_metadata",
        "root_metadata_entrypoint_hints",
        "root_metadata_entrypoint_literal_exists",
        "root_start_command_present", "root_type_module",
        "optional_dependency_metadata_keys",
        "literal_import_syntax_occurrences",
        "relative_literal_imports_detected",
        "relative_literal_present_path_hint",
        "relative_literal_missing_path_hint",
        "package_or_builtin_import_hints", "builtin_node_specifier_hints",
        "conditional_platform_references",
        "native_loader_pattern_hints",
        "native_addon_string_hints", "nonliteral_native_import_hints",
        "dynamic_require_unresolved_hints",
        "dynamic_import_unresolved_hints",
        "direct_static_native_addon_imports_present",
        "direct_static_native_addon_imports_missing",
    )
    for k in keys:
        print("P55_" + k.upper() + "=" + str(c[k]))
    print("P55_LITERAL_IMPORTS_ARE_ONLY_LOWER_BOUND=YES")
    print("P55_DESKTOP_NATIVE_ADDONS_OPTIONAL_FOR_ANDROID=NOT_PROVEN")
    print("P55_PRODUCTION_ENTRYPOINT_RESOLVED=NO")
    print("P55_PRODUCTION_MODULE_GRAPH_CLOSED=NO")
    print("P55_PRODUCTION_NODE_RUNTIME_OR_SCRIPTS_EXECUTED=NO")
    print("P55_SOURCE_PATHS_OR_JS_CONTENT_EMITTED=NO")
    print("P55_DSH_ENGINEMANAGER_HANDOFF=NOT_IMPLEMENTED")
    print("P55_SIGNED_V139_APK=BLOCKED")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("signed_original_v138_apk")
    args = p.parse_args()
    print_report(run_exact_original(pathlib.Path(args.signed_original_v138_apk)))
