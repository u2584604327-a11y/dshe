#!/usr/bin/env python3
"""P229: strictly bounded positive-only ART V1 streaming binary prefix decoder.

AOSP ART streaming FORMAT V1:
  32-byte 'SLOW' header -> interleaved thread-0 method/thread metadata tokens
  and fixed-size thread-N method event records -> terminal summary.
This differs from the TEXT-HEADER-FIRST non-streaming .trace format.
Input is a verified <=8MiB prefix of an oversized, never-released offline
Android35 profileable clone trace. Missing data/events are NOT absence proof.
No raw event/method/thread/account/user data printed or uploaded.
"""
import argparse
from pathlib import Path
import struct
import sys
from p220_trace_parser import classify,parse_method_id

MAX_PREFIX=8*1024*1024
MAX_METHOD_TOKENS=100000
LABELS=("START2","NODE_INSTALL","P40_BRIDGE","P47_GATE")
ACTIONS=("ENTER","EXIT","UNROLL")
STAGES={
 "INPUT","HEADER_MAGIC","FORMAT_VERSION","HEADER_LAYOUT","METHOD_TOKEN",
 "THREAD_TOKEN","UNKNOWN_META_TOKEN","SUMMARY_IN_PREFIX",
 "METHOD_KEY_DRIFT","METHOD_TOKEN_COUNT","EVENT_ACTION",
 "NO_COMPLETE_EVENTS","TRUNCATED_HEADER",
}

class Rejected(Exception):
    def __init__(self, stage, *, offset_band="UNKNOWN", preceding="UNKNOWN",
                 valid_events_band="UNKNOWN"):
        super().__init__(stage)
        # P232: strictly enumerable, no raw bytes, offsets, method IDs or names.
        self.offset_band=offset_band
        self.preceding=preceding
        self.valid_events_band=valid_events_band

def _offset_band(position):
    if position < 4096: return "FIRST_4K"
    if position < 262144: return "4K_TO_256K"
    if position < 1048576: return "256K_TO_1M"
    return "AFTER_1M"

def _valid_events_band(count):
    if count == 0: return "ZERO"
    if count < 100: return "ONE_TO_99"
    if count < 10000: return "100_TO_9999"
    return "AT_LEAST_10000"
def need(x,stage):
    if not x:raise Rejected(stage)
def inspect(data):
    need(type(data) is bytes and 32<=len(data)<=MAX_PREFIX,"INPUT")
    need(data[:4]==b"SLOW","HEADER_MAGIC")
    ver=int.from_bytes(data[4:6],"little")
    # AOSP ART streaming format V1 sets 0xF0 on the dual-clock v3 version.
    # Only raw 0xF3 is supported here; do not accept plain v3 or newer V2.
    need(ver==0xF3,"FORMAT_VERSION")
    off=int.from_bytes(data[6:8],"little")
    width=int.from_bytes(data[16:18],"little")
    need(off==32 and width==14 and len(data)>32,"HEADER_LAYOUT")
    pos=off;ids={};counts={k:{a:0 for a in ACTIONS} for k in LABELS}
    events=0;method_tokens=0;thread_tokens=0;cut_last=False
    preceding="HEADER"
    while pos<len(data):
        remaining=len(data)-pos
        if remaining<2:
            cut_last=True
            break
        tid=int.from_bytes(data[pos:pos+2],"little")
        if tid==0:
            if remaining<3:
                cut_last=True
                break
            opcode=data[pos+2]
            if opcode==1:
                if remaining<5:
                    cut_last=True
                    break
                n=int.from_bytes(data[pos+3:pos+5],"little")
                need(n>0,"METHOD_TOKEN")
                if remaining<5+n:
                    cut_last=True
                    break
                method_tokens+=1
                need(method_tokens<=MAX_METHOD_TOKENS,"METHOD_TOKEN_COUNT")
                info=data[pos+5:pos+5+n].decode("utf-8")
                parts=info.rstrip("\n").split("\t")
                need(3<=len(parts)<=12,"METHOD_TOKEN")
                mid=parse_method_id(parts[0])
                kind=classify(parts[1],parts[2])
                if kind in LABELS:
                    need(mid not in ids,"METHOD_KEY_DRIFT")
                    ids[mid]=kind
                pos+=5+n
                preceding="METHOD_META"
            elif opcode==2:
                if remaining<7:
                    cut_last=True
                    break
                n=int.from_bytes(data[pos+5:pos+7],"little")
                if remaining<7+n:
                    cut_last=True
                    break
                thread_tokens+=1
                pos+=7+n
                preceding="THREAD_META"
            elif opcode==3:
                # A summary must be at the end of a full stream. We know the
                # on-device remote file was >16 MiB, so never in first 8 MiB.
                raise Rejected("SUMMARY_IN_PREFIX")
            else:
                raise Rejected("UNKNOWN_META_TOKEN")
        else:
            if remaining<width:
                cut_last=True
                break
            word=struct.unpack_from("<I",data,pos+2)[0]
            action=word&3
            if action>2:
                # P232: preserve rejection; classify where framing first fails.
                raise Rejected("EVENT_ACTION", offset_band=_offset_band(pos),
                               preceding=preceding,
                               valid_events_band=_valid_events_band(events))
            kind=ids.get(word&~3)
            if kind is not None:counts[kind][ACTIONS[action]]+=1
            events+=1
            pos+=width
            preceding="EVENT"
    need(events>0,"NO_COMPLETE_EVENTS")
    return events,method_tokens,thread_tokens,counts,cut_last

def main():
    p=argparse.ArgumentParser()
    p.add_argument("bounded_streaming_prefix")
    a=p.parse_args()
    try:
        f=Path(a.bounded_streaming_prefix)
        need(f.is_file() and not f.is_symlink(),"INPUT")
        need(32<=f.stat().st_size<=MAX_PREFIX,"INPUT")
        events,methods,threads,counts,cut=inspect(f.read_bytes())
    except Exception as error:
        stage=str(error) if isinstance(error,Rejected) and str(error) in STAGES else "UNSUPPORTED_FORMAT_OR_INVALID"
        print("P229_STREAM_PREFIX_REJECTION="+stage)
        if stage=="EVENT_ACTION" and isinstance(error,Rejected):
            print("P232_EVENT_ACTION_OFFSET_BAND="+error.offset_band)
            print("P232_EVENT_ACTION_PRECEDING_PACKET="+error.preceding)
            print("P232_EVENT_ACTION_VALID_EVENTS_BAND="+error.valid_events_band)
            print("P232_EVENT_ACTION_REMAINS_REJECTED=YES")
        print("P229_STREAM_PREFIX_EVENTS=NOT_ATTESTED")
        print("P229_ABSENCE_NOT_PROVEN=YES")
        return 2
    print("P229_AOSP_STREAM_V1_ART_V3_PREFIX=PASS")
    print("P229_STREAM_PREFIX_VALID_EVENT_COUNT="+str(events))
    print("P229_STREAM_PREFIX_METHOD_METADATA_COUNT="+str(methods))
    print("P229_STREAM_PREFIX_THREAD_METADATA_COUNT="+str(threads))
    print("P229_PREFIX_BOUNDARY_PARTIAL_RECORD="+("YES" if cut else "NO"))
    for kind in LABELS:
        for action in ACTIONS:
            number=counts[kind][action]
            print("P229_"+kind+"_"+action+"="+("OBSERVED" if number else "NOT_ATTESTED"))
            print("P229_"+kind+"_"+action+"_COUNT_IN_PREFIX="+str(number))
    print("P229_PARTIAL_STREAM_NOT_COMPLETE_TRACE=YES")
    print("P229_EVENT_ORDER_NOT_PROVEN_SAME_CALLSTACK=YES")
    print("P229_MISSING_EVENT_IS_NOT_ABSENCE_PROOF=YES")
    print("P229_NODE_EXIT_NOT_SUCCESS_RETURN_OR_ORIGINAL_PC=YES")
    print("P229_NO_RAW_METHOD_NAME_THREAD_PID_ACCOUNT_OR_TRACE=YES")
    print("P229_FORMAL_V139=STRUCTURAL_BLOCKED")
    return 0

if __name__=="__main__":
    sys.exit(main())
