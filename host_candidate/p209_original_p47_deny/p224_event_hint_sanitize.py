#!/usr/bin/env python3
"""P224 bounded sanitized Android35 event-buffer hints; NEVER raw log output.

Event tag/substring evidence is not a forensic cause-of-death proof. Only a
disposable offline emulator can be used by the invoking shell. No app data,
PID, UID, class/permission names or arbitrary event lines are printed.
"""
import re,sys
MAX=256*1024
PKG=re.compile(r"(?<![A-Za-z0-9_.])com\.dsh\.android(?![A-Za-z0-9_.])")
TAGS=("am_proc_start","am_proc_died","am_crash","am_anr","am_kill")
RE_TAG=re.compile(r"\b(am_proc_start|am_proc_died|am_crash|am_anr|am_kill):")
def classify(raw,old,new):
    if type(raw) is not bytes or len(raw)>MAX:raise ValueError("P224_SIZE")
    if not re.fullmatch(r"[1-9][0-9]{1,7}",old or "") or not re.fullmatch(r"[1-9][0-9]{1,7}",new or ""):raise ValueError("P224_PID")
    text=raw.decode("utf-8",errors="replace")
    result={x:0 for x in TAGS}
    old_death=0
    new_start=0
    for line in text.splitlines()[:2000]:
        if not PKG.search(line):continue
        m=RE_TAG.search(line)
        if m is None:continue
        tag=m.group(1)
        result[tag]+=1
        if tag=="am_proc_died" and re.search(r"(?<!\d)"+re.escape(old)+r"(?!\d)",line):old_death+=1
        if tag=="am_proc_start" and re.search(r"(?<!\d)"+re.escape(new)+r"(?!\d)",line):new_start+=1
    return result,old_death,new_start
def main():
    try:
        if len(sys.argv)!=3:raise ValueError("args")
        old,new=sys.argv[1:3]
        raw=sys.stdin.buffer.read(MAX+1)
        counts,death,start=classify(raw,old,new)
    except Exception:
        print("P224_EVENT_AUDIT=NOT_ATTESTED")
        return 2
    for label in TAGS:
        print("P224_EVENT_"+label.upper()+"_APP_HINT="+
              ("OBSERVED" if counts[label] else "NOT_OBSERVED"))
    print("P224_OLD_PID_DEATH_EVENT_HINT="+("OBSERVED" if death else "NOT_OBSERVED"))
    print("P224_NEW_PID_START_EVENT_HINT="+("OBSERVED" if start else "NOT_OBSERVED"))
    print("P224_EVENT_BUFFER_IS_NOT_CAUSAL_ORIGINAL_PC_EVIDENCE=YES")
    print("P224_RAW_EVENTS_AND_PID_PRINTED=NO")
    print("P224_EVENT_SANITIZED_READONLY_AUDIT=PASS")
    return 0
if __name__=="__main__":sys.exit(main())
