#!/usr/bin/env python3
"""P212: two bounded, redacted disposable-emulator activity snapshots.

No original APK change. Reads only local ephemeral ADB dumpsys snapshots and
prints whitelisted classifications, never original activity/window text, app
secrets, PIDs, tokens, arguments, account names, raw stacks or event logs.
A snapshot classifies state at ONE instant; no Android action is initiated.
"""
import argparse
from pathlib import Path
import re
import sys

PACKAGE="com.dsh.android"
MAIN="MainActivity"
LIMIT=2_000_000
RESUMED_RE=re.compile(
    r"(?:mResumedActivity|topResumedActivity|mTopResumedActivity|ResumedActivity)"
    r"\s*[:=]", re.I)
FOCUS_RE=re.compile(r"(?:mCurrentFocus|mFocusedApp)\s*[:=]",re.I)
COMPONENT_RE=re.compile(r"\b[a-zA-Z][a-zA-Z0-9_.]+/[.]?[A-Za-z0-9_.$]+")
VALID_PID=re.compile(r"[0-9]{2,8}")

def signal(lines,regex):
    matches=[line.strip() for line in lines.splitlines() if regex.search(line)]
    if not matches:return "UNKNOWN"
    if len(matches)>12:return "AMBIGUOUS"
    labels=[]
    for line in matches:
        if re.search(r"[:=]\s*null\b",line,re.I):
            labels.append("NO_TARGET")
        elif COMPONENT_RE.search(line):
            # Disclose only classification, never other package or component.
            if re.search(r"\b"+re.escape(PACKAGE)+r"/\.?(?:"
                         +re.escape(PACKAGE)+r"\.)?"+re.escape(MAIN)
                         +r"\b",line):
                labels.append("MAIN")
            elif re.search(r"\b"+re.escape(PACKAGE)+r"/",line):
                labels.append("SAME_PACKAGE_OTHER")
            else:
                labels.append("EXTERNAL_COMPONENT")
        elif PACKAGE in line and MAIN in line:
            # Android variants may omit slash; class+package alone is
            # insufficient evidence of an *actual* resumed component.
            labels.append("UNKNOWN")
        else:
            labels.append("UNKNOWN")
    unique=set(labels)
    return next(iter(unique)) if len(unique)==1 else "AMBIGUOUS"

def frame(pid,pidof,activities,windows):
    if not VALID_PID.fullmatch(pid):
        raise ValueError("P212_INVALID_HOST_PID")
    actual=pidof.split()
    if not actual:process="GONE"
    elif len(actual)==1 and actual[0]==pid:process="ALIVE_SAME"
    else:process="PID_DRIFT_OR_MULTIPLE"
    return (process,signal(activities,RESUMED_RE),
            signal(windows,FOCUS_RE))

def transition(early,late):
    if early[0]!="ALIVE_SAME" or late[0]!="ALIVE_SAME":
        return "NO_STABLE_PROCESS"
    a,b=early[1],late[1]
    if a=="MAIN" and b=="MAIN":return "MAIN_RESUMED_BOTH"
    if a=="MAIN" and b in ("SAME_PACKAGE_OTHER","EXTERNAL_COMPONENT","NO_TARGET"):
        return "MAIN_WAS_RESUMED_THEN_NOT"
    if a in ("SAME_PACKAGE_OTHER","EXTERNAL_COMPONENT","NO_TARGET") and b=="MAIN":
        return "MAIN_BECAME_RESUMED"
    if a in ("SAME_PACKAGE_OTHER","EXTERNAL_COMPONENT","NO_TARGET") and        b in ("SAME_PACKAGE_OTHER","EXTERNAL_COMPONENT","NO_TARGET"):
        return "MAIN_NOT_RESUMED_IN_EITHER_SNAPSHOT"
    return "INSUFFICIENT_RESUMED_EVIDENCE"

def limited(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink() or not 0<=p.stat().st_size<=LIMIT:
        raise ValueError("P212_BOUND_OR_SYMLINK")
    return p.read_text(encoding="utf8",errors="replace")

def evaluate(pid,prefix):
    return frame(pid,limited(prefix+".pidof"),
                 limited(prefix+".activities"),limited(prefix+".windows"))

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--host-pid",required=True)
    ap.add_argument("--early-prefix",required=True)
    ap.add_argument("--late-prefix",required=True)
    args=ap.parse_args()
    try:
        early=evaluate(args.host_pid,args.early_prefix)
        late=evaluate(args.host_pid,args.late_prefix)
        kind=transition(early,late)
    except (ValueError,OSError):
        print("P212_ACTIVITY_TRANSITION=DENY_UNRELIABLE_SNAPSHOT",file=sys.stderr)
        return 2
    for stage,result in (("EARLY",early),("LATE",late)):
        print("P212_"+stage+"_HOST_PROCESS="+result[0])
        print("P212_"+stage+"_RESUMED_COMPONENT="+result[1])
        print("P212_"+stage+"_FOCUSED_COMPONENT="+result[2])
    print("P212_RESUMED_TRANSITION="+kind)
    print("P212_TWO_SNAPSHOTS_NOT_FULL_LIFECYCLE_HISTORY=YES")
    print("P212_NO_RAW_DUMPSYS_OR_ACCOUNT_CONTENT_EXPOSED=YES")
    print("P212_ORIGINAL_ENGINE_PC3912_RUNTIME=NOT_ATTESTED")
    print("P212_ORIGINAL_APK_OR_UI_INTERACTION_MUTATED=NO")
    print("P212_V139_RELEASE=STRUCTURAL_BLOCKED")
    print("P212_REDACTED_TWO_SNAPSHOT_AUDIT=PASS")
    return 0

if __name__=="__main__":
    sys.exit(main())
