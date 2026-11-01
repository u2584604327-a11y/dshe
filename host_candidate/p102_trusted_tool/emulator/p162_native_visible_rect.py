#!/usr/bin/env python3
"""P162: coordinates from the already-visible native ZERO-permission lab button,
never from guesses/host screen size. Require a fresh pending generation.

This is a CI-only standalone synthetic test and not a real-user approval oracle.
"""
import pathlib
import re
import sys

PENDING="P102_REAL_BINDER_PENDING_NATIVE_APPROVAL=PASS"
REVOKED="P102_NATIVE_BACKGROUND_REVOKE=PASS"
FOCUS_YES="P102_NATIVE_WINDOW_FOCUS=YES"
FOCUS_NO="P102_NATIVE_WINDOW_FOCUS=NO"
GEOMETRY=re.compile(r"\bP162_VISIBLE_NATIVE_APPROVAL_RECT=(\d+),(\d+),(\d+),(\d+)(?![0-9,])")

def verified_center(text):
    lines=text.splitlines()
    if len(lines)>10000 or len(text)>262144:
        raise ValueError("P162_LOG_BOUNDS")
    pending=[i for i,line in enumerate(lines) if PENDING in line]
    revoked=[i for i,line in enumerate(lines) if REVOKED in line]
    focus=[(i,FOCUS_YES if FOCUS_YES in line else FOCUS_NO)
           for i,line in enumerate(lines)
           if FOCUS_YES in line or FOCUS_NO in line]
    if not pending or not focus or focus[-1][1]!=FOCUS_YES:
        raise ValueError("P162_NO_NATIVE_FOCUSED_PENDING")
    if revoked and revoked[-1]>pending[-1]:
        raise ValueError("P162_PENDING_ALREADY_REVOKED")
    if any("P102_TRUSTED_EXECUTION_COUNT=" in line or
           "P102_NATIVE_UI_APPROVAL_DISPATCH=" in line for line in lines):
        raise ValueError("P162_ALREADY_EXECUTED_OR_DISPATCHED")
    geometry=[]
    for i,line in enumerate(lines):
        found=GEOMETRY.search(line)
        if found and i>pending[-1] and i>=focus[-1][0]:
            geometry.append(tuple(int(x) for x in found.groups()))
    if not geometry:
        raise ValueError("P162_NO_FOCUSED_NATIVE_VIEW_GEOMETRY")
    if len(set(geometry))>1:
        raise ValueError("P162_GEOMETRY_AMBIGUOUS")
    a,b,c,d=geometry[-1]
    if not(0<=a<c<=10000 and 0<=b<d<=10000 and c-a>=8 and d-b>=8):
        raise ValueError("P162_INVALID_NATIVE_VIEW_RECT")
    return (a+c)//2,(b+d)//2

def main():
    if len(sys.argv)!=2:
        raise SystemExit("P162_USAGE_DENIED")
    p=pathlib.Path(sys.argv[1])
    if not p.is_file() or p.is_symlink() or p.stat().st_size>262144:
        raise SystemExit("P162_LOG_MISSING_OR_OVERSIZE")
    try:
        x,y=verified_center(p.read_text(encoding="utf-8"))
    except (ValueError,UnicodeError) as e:
        raise SystemExit(str(e))
    print(f"{x} {y}")

if __name__=="__main__":
    main()
