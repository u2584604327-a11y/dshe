#!/usr/bin/env python3
"""P114 SHA-locked exact-v138 original call-dispatch identifier audit.

Inspect bounded source identifiers inside the exact ORIGINAL bundled engine.
Only safe paths/symbol counts/export/import names are emitted; never source,
token, user session content, APK entries or private original code bytes.
This is provenance, not a production hook implementation or license grant.
"""
import argparse
import gzip
import hashlib
import io
import pathlib
import re
import tarfile
import zipfile

APK_SHA="3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5"
APK_SIZE=147341486
PACKAGE_PREFIXES=(
  "node_modules/@deepseek-ai/dsh-agent-loop/",
  "node_modules/@deepseek-ai/dsh-tools/",
  "node_modules/@deepseek-ai/dsh-user-approval/",
)
MAX_FILES=55000
MAX_SOURCE=4_000_000
MAX_ENGINE=360_000_000

def digest(path):
  h=hashlib.sha256()
  with path.open("rb") as fh:
    for chunk in iter(lambda:fh.read(1024*1024),b""):h.update(chunk)
  return h.hexdigest()

def scan(path):
  assert path.is_file() and path.stat().st_size==APK_SIZE,"P114_APK_SIZE_DRIFT"
  assert digest(path)==APK_SHA,"P114_APK_SHA_DRIFT"
  with zipfile.ZipFile(path) as z:
    entry=z.getinfo("assets/engine.bin")
    assert entry.file_size<=MAX_ENGINE,"P114_ENGINE_SIZE_LIMIT"
    engine=z.read(entry)
  matches=[]
  for_count=0
  with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(engine)),mode="r|") as tf:
    for_count+=1
    for member in tf:
      for_count+=1
      assert for_count<=MAX_FILES,"P114_TAR_ENTRY_LIMIT"
      name=member.name.lstrip("./")
      if not member.isfile() or not name.startswith(PACKAGE_PREFIXES):
        continue
      if not name.endswith((".js",".mjs",".cjs")):
        continue
      assert 0<=member.size<=MAX_SOURCE,"P114_JS_SIZE_LIMIT"
      fh=tf.extractfile(member)
      assert fh is not None,"P114_MEMBER_STREAM"
      data=fh.read(MAX_SOURCE+1)
      assert len(data)==member.size,"P114_MEMBER_BYTES"
      refs=data.count(b"executeToolCalls")
      if refs==0:continue
      decl=bool(re.search(rb"\b(?:async\s+)?function\s+executeToolCalls\s*\(",data))
      assigned=bool(re.search(rb"\b(?:const|let|var)\s+executeToolCalls\b",data))
      invoked=len(re.findall(rb"\bexecuteToolCalls\s*\(",data))
      imported=bool(re.search(rb"\bimport\s*\{[^}]{0,1000}\bexecuteToolCalls\b",data,re.S))
      # Relative module import specifiers, NOT source/code bodies.
      sources=[]
      for found in re.findall(rb"from\s*['\"]([^'\"\n]{1,140})['\"]",data):
        value=found.decode("utf-8","replace")
        if re.fullmatch(r"[@A-Za-z0-9_./-]{1,140}",value):sources.append(value)
      matches.append({
        "path":name,"references":refs,"invocations":invoked,
        "functionDeclared":decl,"varDeclared":assigned,
        "namedImported":imported,"imports":sorted(set(sources))[:12],
      })
  assert any("/dsh-agent-loop/" in r["path"] for r in matches),"P114_ORIGINAL_HELPER_NOT_FOUND"
  print("P114_ORIGINAL_V138_ENGINE_SHA_LOCK=PASS")
  print("P114_ORIGINAL_DISPATCH_IDENTIFIER_AUDIT=PASS")
  for row in sorted(matches,key=lambda x:x["path"]):
    print("P114_CALLSITE_PATH="+row["path"])
    print("P114_CALLSITE_REFS="+str(row["references"]))
    print("P114_CALLSITE_CALLS="+str(row["invocations"]))
    print("P114_CALLSITE_DECLARE="+str(row["functionDeclared"]).lower())
    print("P114_CALLSITE_IMPORT="+str(row["namedImported"]).lower())
    # Import names only (not executable source)
    print("P114_CALLSITE_MODULE_IMPORTS="+",".join(row["imports"]))
  print("P114_TOOLRUNTIME_EXECUTE_AUTHORITY=NOT_PROVEN")
  print("P114_ORIGINAL_PENDING_CALL_TO_NATIVE_BINDER=NOT_WIRED")
  print("P114_ORIGINAL_ENGINE_SOURCE_BYTES_EXPORTED=NO")

if __name__=="__main__":
  parser=argparse.ArgumentParser()
  parser.add_argument("--original",type=pathlib.Path,required=True)
  a=parser.parse_args()
  scan(a.original)
