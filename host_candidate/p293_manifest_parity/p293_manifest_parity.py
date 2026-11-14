#!/usr/bin/env python3
"""P293 CI-only strict *byte-preserving* Manifest member restoration.

P43's existing builder replaces Apktool's plaintext AndroidManifest.xml with
AAPT binary AXML. P292's temporary smali reassembly omitted that replacement.
This script stages the *already validated P43 baseline member* byte-for-byte,
without interpreting, rewriting, canonically comparing or weakening P245.
Unknown data, duplicate members, non-AXML baseline or nonplaintext candidate
must fail closed. This never touches user APKs or any source-side manifest.
"""
import argparse,hashlib,re,sys,zipfile
from pathlib import Path
sys.path[:0]=["host_candidate/p249_dual_diff","host_candidate/p246_exception_semantics"]
from p249_dual_diff import seal

BASE=Path(".p43tmp/P43-ORIGINAL-DSH-EPHEMERAL-EMULATOR-ONLY.apk")
SIGNED=Path(".p43tmp/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk")
CANDIDATE=Path(".p245tmp/P294-UNSIGNED-DO-NOT-INSTALL.apk")
STAGED=Path(".p245tmp/p293-staged-manifest/AndroidManifest.xml")
MEMBER="AndroidManifest.xml"
AXML_HEAD=b"\x03\x00\x08\x00"
LIMIT=4194304

def kind(blob):
    if not isinstance(blob,bytes) or not 0<len(blob)<=LIMIT:
        return "UNKNOWN"
    if len(blob)>=8 and blob[:4]==AXML_HEAD:
        declared=int.from_bytes(blob[4:8],"little")
        if declared==len(blob):
            return "BINARY_AXML"
        return "UNKNOWN"
    try:
        s=blob.decode("utf-8-sig").lstrip()
    except UnicodeError:
        return "UNKNOWN"
    if ("\x00" not in s and (s.startswith("<?xml ") or
                             s.startswith("<manifest ") or
                             s.startswith("<manifest>"))):
        return "PLAINTEXT_XML"
    return "UNKNOWN"

def classify(base,candidate):
    if kind(base)!="BINARY_AXML":
        return "DENY_BASE_NOT_BINARY"
    if kind(candidate)!="PLAINTEXT_XML":
        return "DENY_CANDIDATE_NOT_PLAINTEXT"
    if base==candidate:
        return "DENY_NOT_DISTINCT"
    return "COPY_BASELINE_BINARY_ONLY"

def verified_member(archive):
    """Unique, non-symlink APK ZIP member with validated zip CRC."""
    if not archive.is_file() or archive.is_symlink():
        raise ValueError("P293_DENY_INPUT")
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None or z.namelist().count(MEMBER)!=1:
            raise ValueError("P293_DENY_ZIP")
        value=z.read(MEMBER)
    if not 0<len(value)<=LIMIT:
        raise ValueError("P293_DENY_SIZE")
    return value

def stage():
    seal(SIGNED)
    if STAGED.exists() or STAGED.is_symlink():
        raise ValueError("P293_DENY_STAGE_ALREADY_EXISTS")
    base=verified_member(BASE)
    candidate=verified_member(CANDIDATE)
    if classify(base,candidate)!="COPY_BASELINE_BINARY_ONLY":
        raise ValueError("P293_DENY_FORMAT")
    STAGED.parent.mkdir(parents=True,exist_ok=True)
    if STAGED.parent.is_symlink():
        raise ValueError("P293_DENY_STAGE_SYMLINK")
    STAGED.write_bytes(base)
    if STAGED.read_bytes()!=base:
        raise ValueError("P293_DENY_STAGE_INTEGRITY")
    print("P293_BASE_MANIFEST=BINARY_AXML")
    print("P293_PRE_REPACK_CANDIDATE_MANIFEST=PLAINTEXT_XML")
    print("P293_STAGE_FROM_VALIDATED_BASE=BYTE_EXACT")
    print("P293_ORIGINAL_APK_AND_P245_GATE=UNMODIFIED")
    print("P293_NO_RELEASE=YES")

def verify():
    seal(SIGNED)
    base=verified_member(BASE)
    candidate=verified_member(CANDIDATE)
    if kind(base)!="BINARY_AXML" or candidate!=base or kind(candidate)!="BINARY_AXML":
        raise ValueError("P293_DENY_BINARY_PARITY")
    with zipfile.ZipFile(BASE) as a,zipfile.ZipFile(CANDIDATE) as b:
        if (a.namelist().count(MEMBER)!=1 or b.namelist().count(MEMBER)!=1):
            raise ValueError("P293_DENY_DUPLICATE")
    print("P293_FINAL_MANIFEST=BINARY_AXML")
    print("P293_FINAL_MANIFEST_MEMBER=BYTE_EXACT_BASELINE")
    print("P293_P245_ORIGINAL_BYTE_PARITY_PREDICATE=UNCHANGED")
    print("P293_NO_RELEASE=YES")

def main():
    p=argparse.ArgumentParser()
    actions=p.add_mutually_exclusive_group()
    actions.add_argument("--stage",action="store_true")
    actions.add_argument("--verify",action="store_true")
    a=p.parse_args()
    try:
        if a.stage:stage()
        elif a.verify:verify()
        else:
            print("P293_SOURCE_ONLY=YES")
            print("P293_REAL_MANIFEST=NOT_ATTESTED")
            print("P293_P245_BYTE_PARITY_PREDICATE=UNMODIFIED")
            print("P293_NO_RELEASE=YES")
    except Exception:
        print("P293_DENY_MANIFEST_FORMAT_OR_BYTE_PARITY",file=sys.stderr)
        return 2
    return 0

if __name__=="__main__":
    raise SystemExit(main())
