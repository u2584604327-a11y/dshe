#!/usr/bin/env python3
"""P100 exact-original underArchivedSession contract, safe identifiers only.

Inputs are fixed-identity original APK bytes. Source, user data, prompts,
credentials, full paths and source expressions are never emitted.
"""
import argparse, gzip, io, json, pathlib, re, tarfile, zipfile
from p96_original_engine_owner import SOURCE_BYTES, SOURCE_SHA, file_hash, require, sha

ROOT = "node_modules/@deepseek-ai/dsh-api-session-controller/"
MAX_MEMBER = 3_000_000
FRAME_LINE = 2533
IDENT = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,80}$")
INCLUDES = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\?\.|\.)[A-Za-z_$][A-Za-z0-9_$]*){0,7})(\?\.|\.)includes\s*\(")
FUNCTION = re.compile(r"\b(?:function\s+)?underArchivedSession\s*\(([^()]{0,400})\)")

def inspect(apk: pathlib.Path):
    require(apk.stat().st_size == SOURCE_BYTES, "APK_SIZE_DRIFT")
    require(file_hash(apk) == SOURCE_SHA, "APK_SHA_DRIFT")
    with zipfile.ZipFile(apk) as z:
        require(z.testzip() is None, "APK_CRC")
        engine = z.read("assets/engine.bin")
    count = 0
    matches = []
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)), mode="r|") as tar:
        for item in tar:
            count += 1
            require(count <= 50000, "TAR_COUNT")
            if not (item.isfile() and item.name.startswith(ROOT) and
                    item.name.endswith((".js", ".mjs", ".cjs"))):
                continue
            require(0 <= item.size <= MAX_MEMBER, "JS_SIZE")
            file = tar.extractfile(item)
            require(file is not None, "JS_READ")
            raw = file.read(MAX_MEMBER + 1)
            require(len(raw) == item.size, "JS_LENGTH")
            if b"underArchivedSession" not in raw:
                continue
            source = raw.decode("utf-8", "strict")
            pkg = item.name.split("/")[2]
            package = pkg if IDENT.fullmatch(pkg) else "UNKNOWN"
            mentions = [source.count("\n", 0, m.start()) + 1
                        for m in re.finditer(r"\bunderArchivedSession\b", source)]
            if not any(abs(line - FRAME_LINE) <= 150 for line in mentions):
                continue
            signatures = []
            for m in FUNCTION.finditer(source):
                lineno = source.count("\n", 0, m.start()) + 1
                if abs(lineno - FRAME_LINE) > 150:
                    continue
                params = [x.strip() for x in m.group(1).split(",")]
                signatures.append({"line": lineno,
                                   "parameters": [x for x in params if IDENT.fullmatch(x)][:12]})
            receivers = []
            for m in INCLUDES.finditer(source):
                line = source.count("\n", 0, m.start()) + 1
                if abs(line - FRAME_LINE) > 25:
                    continue
                receivers.append({"line": line,
                                  "receiver": m.group(1).replace("?.", "."),
                                  "optional": m.group(2) == "?.",
                                  "atCaughtLine": abs(line - FRAME_LINE) <= 2})
            matches.append({"package": package,
                            "moduleSha12": sha(raw)[:12],
                            "reportedFrameLine": FRAME_LINE,
                            "underArchivedSessionMentions": mentions[:30],
                            "functionSignatures": signatures[:12],
                            "nearbyIncludes": receivers[:40]})
    print("P100_UNDER_ARCHIVED_SESSION_CONTRACT=" +
          json.dumps(matches, sort_keys=True))
    print("P100_UNDER_ARCHIVED_SESSION_SOURCE_EXPORTED=NO")
    print("P100_UNDER_ARCHIVED_SESSION_SCAN=" +
          ("PASS" if matches else "NOT_FOUND"))
    require(bool(matches), "UNDER_ARCHIVED_SESSION_NOT_FOUND")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    args = parser.parse_args()
    inspect(pathlib.Path(args.original))
