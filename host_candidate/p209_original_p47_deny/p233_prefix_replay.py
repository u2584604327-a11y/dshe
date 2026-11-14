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

def length_band(size):
    """Fixed enum only; do not print byte counts or any trace bytes."""
    if not isinstance(size,int) or size < 0:
        return "UNKNOWN"
    if size == 0:
        return "EMPTY"
    delta = size - EXPECTED
    if delta == 0:
        return "EXACT_7M"
    if delta < 0:
        difference = -delta
        if difference <= 64: return "SHORT_1_TO_64"
        if difference <= 4096: return "SHORT_65_TO_4096"
        if difference <= 65536: return "SHORT_4097_TO_65536"
        return "SHORT_OVER_65536"
    if delta <= 64: return "OVER_1_TO_64"
    if delta <= 4096: return "OVER_65_TO_4096"
    if delta <= 65536: return "OVER_4097_TO_65536"
    return "OVER_OVER_65536"

def file_length_band(path):
    try:
        file = Path(path)
        if file.is_symlink() or not file.is_file():
            return "UNSAFE_OR_MISSING"
        return length_band(file.stat().st_size)
    except OSError:
        return "UNKNOWN"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("first")
    parser.add_argument("second")
    args = parser.parse_args()
    result = audit(args.first, args.second)
    if result not in STATES:
        result = "IO_ERROR"
    # P234: always emit independent sizes as enums, including on DENY.
    # No exact lengths, bytes, hashes, pathnames or trace metadata.
    print("P234_FIRST_PREFIX_LENGTH_BAND=" + file_length_band(args.first))
    print("P234_REPLAY_PREFIX_LENGTH_BAND=" + file_length_band(args.second))
    print("P233_PREFIX_EXACT_STABLE_REPLAY=" + result)
    print("P233_NO_PREFIX_BYTES_OR_HASHES_EXPOSED=YES")
    return 0 if result == "PASS" else 2

if __name__ == "__main__":
    raise SystemExit(main())
