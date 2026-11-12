#!/usr/bin/env python3
"""P233: exact-size, byte-identical bounded ART prefix replay; no trace output."""
import argparse
from pathlib import Path

EXPECTED = 112 * 65536
CHUNK = 65536
STATES = frozenset({"PASS","INVALID_INPUT","SIZE_MISMATCH","DIFFERENT","IO_ERROR"})

def audit(first, second):
    a, b = Path(first), Path(second)
    try:
        if a.absolute() == b.absolute():
            return "INVALID_INPUT"
        if a.is_symlink() or b.is_symlink() or not a.is_file() or not b.is_file():
            return "INVALID_INPUT"
        if a.stat().st_size != EXPECTED or b.stat().st_size != EXPECTED:
            return "SIZE_MISMATCH"
        with a.open("rb") as af, b.open("rb") as bf:
            for _ in range(EXPECTED // CHUNK):
                if af.read(CHUNK) != bf.read(CHUNK):
                    return "DIFFERENT"
        return "PASS"
    except OSError:
        return "IO_ERROR"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("first")
    parser.add_argument("second")
    args = parser.parse_args()
    result = audit(args.first, args.second)
    if result not in STATES:
        result = "IO_ERROR"
    print("P233_PREFIX_EXACT_STABLE_REPLAY=" + result)
    print("P233_NO_PREFIX_BYTES_OR_HASHES_EXPOSED=YES")
    return 0 if result == "PASS" else 2

if __name__ == "__main__":
    raise SystemExit(main())
