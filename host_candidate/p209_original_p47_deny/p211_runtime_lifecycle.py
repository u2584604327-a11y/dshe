#!/usr/bin/env python3
"""P211 Android35 original-entry non-observation: safe bounded lifecycle signals.

Consumes only in-memory or local disposable-emulator adb diagnostic snapshots.
Never prints raw dumpsys, package state, device IDs, account data, log lines,
process UID, paths or Android launch arguments. No Android mutation.
"""
import argparse
from pathlib import Path
import re
import sys

PACKAGE="com.dsh.android"
MAIN="MainActivity"
MAX_INPUT=2_000_000

def classify(host_pid, pidof, activities, windows):
    if not re.fullmatch(r"[0-9]{2,8}",host_pid):
        raise ValueError("P211_INVALID_HOST_PID")
    actual=pidof.strip().split()
    if len(actual)==0:
        process="NO"
    elif len(actual)==1 and actual[0]==host_pid:
        process="YES"
    else:
        process="DRIFT_OR_MULTIPLE"
    resumed=[line.strip() for line in activities.splitlines()
             if re.search(r"(topResumedActivity|mResumedActivity|ResumedActivity)",line)]
    focus=[line.strip() for line in windows.splitlines()
           if "mCurrentFocus=" in line or "mFocusedApp=" in line]
    def status(lines):
        if not lines:return "UNKNOWN"
        is_main=sum(PACKAGE in line and MAIN in line for line in lines)
        if len(lines)>8:return "AMBIGUOUS"
        if is_main==len(lines):return "YES"
        if is_main==0:return "NO"
        return "MIXED"
    a=status(resumed)
    f=status(focus)
    classification=("FOREGROUND_MAIN_AND_LIVE" if process=="YES" and
                    (a=="YES" or f=="YES") else
                    "PROCESS_ALIVE_NOT_PROVEN_FOREGROUND" if process=="YES" else
                    "PROCESS_NOT_STABLE_OR_GONE")
    return process,a,f,classification

def limited(path):
    p=Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size>MAX_INPUT:
        raise ValueError("P211_DISPOSABLE_SNAPSHOT_BOUND")
    return p.read_text(encoding="utf-8",errors="replace")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--host-pid",required=True)
    parser.add_argument("--pidof-snapshot",required=True)
    parser.add_argument("--activity-snapshot",required=True)
    parser.add_argument("--window-snapshot",required=True)
    args=parser.parse_args()
    try:
        process,resumed,focus,kind=classify(args.host_pid,
            limited(args.pidof_snapshot),limited(args.activity_snapshot),
            limited(args.window_snapshot))
    except (ValueError,OSError):
        print("P211_RUNTIME_DIAGNOSTIC=DENY_UNRELIABLE_INPUT",file=sys.stderr)
        return 2
    print("P211_SAME_HOST_PID_SURVIVED="+process)
    print("P211_MAIN_ACTIVITY_RESUMED_SNAPSHOT="+resumed)
    print("P211_MAIN_WINDOW_FOCUSED_SNAPSHOT="+focus)
    print("P211_NONOBSERVATION_CLASS="+kind)
    print("P211_DUMPSYS_ORIGINAL_STRINGS_EXPOSED=NO")
    print("P211_RUNTIME_EMULATOR_SNAPSHOT_ONLY=YES")
    print("P211_NODE_OR_P47_RUNTIME_REACHABILITY=NOT_ATTESTED")
    print("P211_V139_RELEASE=STRUCTURAL_BLOCKED")
    return 0

if __name__=="__main__":
    sys.exit(main())
