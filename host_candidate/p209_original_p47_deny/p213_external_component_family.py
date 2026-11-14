#!/usr/bin/env python3
"""P213: coarse classification of disposable Android35 resumed component.

No process, package/component identifiers, original dumpsys, screenshots,
account data or logs are emitted. Strictly reuses the two P212 snapshots and
does not query Android or modify APK, process, window, task or permissions.
"""
import argparse
import re
import sys

from p212_activity_transition import (
    PACKAGE, COMPONENT_RE, RESUMED_RE, FOCUS_RE, limited,
)

FAMILIES={
    "com.android.launcher3":"LAUNCHER",
    "com.google.android.apps.nexuslauncher":"LAUNCHER",
    "com.android.launcher":"LAUNCHER",
    "com.android.systemui":"SYSTEM_UI",
    "com.android.permissioncontroller":"PERMISSION_CONTROLLER",
    "com.google.android.permissioncontroller":"PERMISSION_CONTROLLER",
    "com.android.settings":"SETTINGS",
}
SAFE_OUTPUT=frozenset({
    "LAUNCHER","SYSTEM_UI","PERMISSION_CONTROLLER",
    "SETTINGS","OTHER_EXTERNAL","SAME_APPLICATION",
    "NO_TARGET","UNKNOWN","AMBIGUOUS",
})

def classify_family(data, selector):
    matches=[line.strip() for line in data.splitlines()
             if selector.search(line)]
    if not matches:return "UNKNOWN"
    if len(matches)>12:return "AMBIGUOUS"
    result=[]
    for line in matches:
        if re.search(r"[:=]\s*null\b",line,re.I):
            result.append("NO_TARGET")
            continue
        components=COMPONENT_RE.findall(line)
        if len(components)!=1:
            result.append("UNKNOWN")
            continue
        package=components[0].split("/",1)[0]
        if package==PACKAGE:result.append("SAME_APPLICATION")
        else:result.append(FAMILIES.get(package,"OTHER_EXTERNAL"))
    distinct=set(result)
    name=next(iter(distinct)) if len(distinct)==1 else "AMBIGUOUS"
    if name not in SAFE_OUTPUT:
        raise ValueError("P213_UNSUPPORTED_CATEGORY")
    return name

def classify_pair(prefix):
    return (classify_family(limited(prefix+".activities"),RESUMED_RE),
            classify_family(limited(prefix+".windows"),FOCUS_RE))

def interpret(early,late):
    e,l=early[0],late[0]
    if e==l and e in ("LAUNCHER","SYSTEM_UI","PERMISSION_CONTROLLER",
                      "SETTINGS","OTHER_EXTERNAL"):
        return "SAME_EXTERNAL_FAMILY_AT_BOTH_INSTANTS"
    if e=="SAME_APPLICATION" and l not in ("SAME_APPLICATION","UNKNOWN","AMBIGUOUS"):
        return "APPLICATION_TO_NONAPPLICATION_BETWEEN_SNAPSHOTS"
    if e in ("UNKNOWN","AMBIGUOUS") or l in ("UNKNOWN","AMBIGUOUS"):
        return "INSUFFICIENT_EXTERNAL_CLASSIFICATION"
    if e!=l:return "FAMILY_CHANGED_BETWEEN_SNAPSHOTS"
    return "NO_CONFIRMED_EXTERNAL_TRANSITION"

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--early-prefix",required=True)
    p.add_argument("--late-prefix",required=True)
    a=p.parse_args()
    try:
        early=classify_pair(a.early_prefix)
        late=classify_pair(a.late_prefix)
        state=interpret(early,late)
    except (ValueError,OSError):
        print("P213_EXTERNAL_CATEGORY=DENY_UNRELIABLE_SNAPSHOT",file=sys.stderr)
        return 2
    print("P213_EARLY_RESUMED_FAMILY="+early[0])
    print("P213_EARLY_WINDOW_FAMILY="+early[1])
    print("P213_LATE_RESUMED_FAMILY="+late[0])
    print("P213_LATE_WINDOW_FAMILY="+late[1])
    print("P213_EXTERNAL_FAMILY_TRANSITION="+state)
    print("P213_CONCRETE_COMPONENT_IDENTITY_LOGGED=NO")
    print("P213_ORIGINAL_DUMPSYS_EXPOSED=NO")
    print("P213_TWO_INSTANTS_DO_NOT_PROVE_ACTIVITY_LIFECYCLE=YES")
    print("P213_REAL_ENGINE_PC3912_OR_NODE_CAUSE=NOT_ATTESTED")
    print("P213_ORIGINAL_APK_AND_USER_DATA_CHANGED=NO")
    print("P213_FORMAL_V139=STRUCTURAL_BLOCKED")
    print("P213_EXTERNAL_FAMILY_CLASSIFIER=PASS")
    return 0

if __name__=="__main__":
    sys.exit(main())
