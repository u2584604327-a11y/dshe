#!/usr/bin/env python3
"""P228: bounded positive-only ART prefix examination, never full-trace absence.

Only used on an >16MiB non-sampling Android35 streaming trace from a
separate disposable profileable test clone. Input is at most 8MiB fetched
via bounded dd; no original APK, user data, method IDs or raw record output.
A valid prefix is NOT a validated complete trace. Missing events are UNKNOWN.
"""
import argparse
from pathlib import Path
import re
import sys
from p226_event_audit import inspect

MAX_PREFIX=8*1024*1024
LABELS=("START2","NODE_INSTALL","P40_BRIDGE","P47_GATE")
ACTIONS=("ENTER","EXIT","UNROLL")

class PrefixInvalid(Exception): pass

def need(condition):
    if not condition: raise PrefixInvalid()

def align_prefix(raw):
    need(type(raw) is bytes and 40<=len(raw)<=MAX_PREFIX)
    end=re.search(br"\*end\r?\n",raw[:min(4*1024*1024,len(raw))])
    need(end is not None and end.start()>0)
    pos=end.end()
    blob=raw[pos:]
    need(len(blob)>=24 and blob[:4]==b"SLOW")
    version=int.from_bytes(blob[4:6],"little")
    offset=int.from_bytes(blob[6:8],"little")
    need(version==3 and 18<=offset<=128 and offset<len(blob))
    recsize=int.from_bytes(blob[16:18],"little")
    need(10<=recsize<=32)
    whole=(len(blob)-offset)//recsize
    need(whole>0)
    trimmed=raw[:pos+offset+whole*recsize]
    need(len(trimmed)<=len(raw) and len(trimmed)>0)
    return trimmed

def audit(raw):
    # Parser rechecks whole available text key table, alignment, actions,
    # binary signature, version, duplicate target IDs and record framing.
    _,n,entries,actions=inspect(align_prefix(raw))
    need(n>0)
    return n,entries,actions

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("bounded_prefix")
    args=ap.parse_args()
    try:
        f=Path(args.bounded_prefix)
        need(f.is_file() and not f.is_symlink())
        need(40<=f.stat().st_size<=MAX_PREFIX)
        n,entries,actions=audit(f.read_bytes())
    except Exception:
        print("P228_BOUNDED_PREFIX=NOT_ATTESTED")
        print("P228_MISSING_EVENTS_DO_NOT_PROVE_ABSENCE=YES")
        return 2
    print("P228_BOUNDED_PREFIX_ART_V3=PASS")
    print("P228_PREFIX_COMPLETE_RECORDS="+str(n))
    for label in LABELS:
        for action in ACTIONS:
            qty=actions[label][action]
            print("P228_"+label+"_"+action+"_EVENT="+
                  ("OBSERVED" if qty else "NOT_ATTESTED"))
            print("P228_"+label+"_"+action+"_COUNT_IN_PREFIX="+str(qty))
    print("P228_PREFIX_IS_NOT_COMPLETE_ART_TRACE=YES")
    print("P228_MISSING_EVENTS_DO_NOT_PROVE_ABSENCE=YES")
    print("P228_EVENT_EXIT_NOT_RETURN_VALUE_OR_INSTALL_SUCCESS=YES")
    print("P228_PROFILED_CLONE_NOT_SIGNED_ORIGINAL_PC=YES")
    print("P228_NO_RAW_TRACE_THREAD_IDS_OR_ACCOUNT_DATA_OUTPUT=YES")
    print("P228_FORMAL_V139=STRUCTURAL_BLOCKED")
    return 0

if __name__=="__main__":
    sys.exit(main())
