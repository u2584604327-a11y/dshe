#!/usr/bin/env python3
"""P226 validate strictly bounded NON-SAMPLED clone ART events, enums only."""
import argparse,sys
from pathlib import Path
from p220_trace_parser import parse,MAX_BYTES,need,trace_size_band
LABELS=("START2","NODE_INSTALL","P40_BRIDGE","P47_GATE")
def inspect(data):
    version,n,entries,actions=parse(data,with_actions=True)
    need(version==3,"P226_ART_V3_REQUIRED")
    need(n>0,"P226_NONEMPTY_EVENT_TABLE_REQUIRED")
    return version,n,entries,actions
def main():
    p=argparse.ArgumentParser();p.add_argument("trace");a=p.parse_args()
    try:
        f=Path(a.trace)
        need(f.is_file() and not f.is_symlink(),"P226_LOCAL_TRACE")
        size=f.stat().st_size
        print("P226_TRACE_SIZE_BAND="+trace_size_band(size))
        need(32<=size<=MAX_BYTES,"P226_SIZE")
        ver,n,entries,actions=inspect(f.read_bytes())
    except Exception:
        print("P226_FULL_METHOD_EVENTS=NOT_ATTESTED")
        print("P226_METHOD_RETURN_VALUE_OR_ORIGINAL_PC=NOT_ATTESTED")
        return 2
    print("P226_TRACE_ART_VERSION="+str(ver))
    print("P226_TRACE_EVENT_TOTAL="+str(n))
    for label in LABELS:
        for action in ("ENTER","EXIT","UNROLL"):
            number=actions[label][action]
            print("P226_"+label+"_"+action+"="+
                  ("OBSERVED" if number else "NOT_ATTESTED"))
            print("P226_"+label+"_"+action+"_COUNT="+str(number))
    print("P226_TRACE_COLLECTION_MODE_PROVEN_BY_SHELL_ONLY=YES")
    print("P226_EVENT_PAIRING_AND_RETURN_VALUES=NOT_ATTESTED")
    print("P226_PROFILING_CHANGES_EXECUTION_TIMING=YES")
    print("P226_NO_RAW_METHODS_OR_USER_DATA=YES")
    print("P226_FORMAL_RELEASE=STRUCTURAL_BLOCKED")
    print("P226_BOUNDED_NON_SAMPLED_ART_AUDIT=PASS")
    return 0
if __name__=="__main__":sys.exit(main())
