#!/usr/bin/env python3
"""P214 offline Android35 PermissionController UI *class-name hints*.

Reads the exact P212 bounded disposable snapshots; prints a tiny fixed enum,
never activity component, class, permission, UID, dump or user data. Class-name
hints do NOT prove an actual permission request or any user action.
"""
import argparse
import re
import sys

from p212_activity_transition import COMPONENT_RE,RESUMED_RE,limited

PERMISSION_PACKAGES=frozenset((
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
))
MAX_RECORDS=12
TYPES={
    "GrantPermissionsActivity":"RUNTIME_GRANT_UI_HINT",
    "ReviewPermissionsActivity":"REVIEW_UI_HINT",
    "ManagePermissionsActivity":"MANAGE_UI_HINT",
    "AppPermissionActivity":"APP_PERMISSION_UI_HINT",
    "PermissionUsageActivity":"USAGE_UI_HINT",
    "ManageApplicationsActivity":"MANAGEMENT_UI_HINT",
}
VALID_CATEGORIES=frozenset(TYPES.values())|frozenset((
    "OTHER_PERMISSION_CONTROLLER_UI",
    "NOT_PERMISSION_CONTROLLER",
    "NO_RESUMED_COMPONENT","AMBIGUOUS","UNKNOWN",
))

def classify(data):
    matches=[line.strip() for line in data.splitlines() if RESUMED_RE.search(line)]
    if not matches:return "NO_RESUMED_COMPONENT"
    if len(matches)>MAX_RECORDS:return "AMBIGUOUS"
    results=[]
    for line in matches:
        if re.search(r"[:=]\s*null\b",line,re.I):
            results.append("NO_RESUMED_COMPONENT")
            continue
        components=COMPONENT_RE.findall(line)
        if len(components)!=1:
            results.append("UNKNOWN")
            continue
        package,cls=components[0].split("/",1)
        if package not in PERMISSION_PACKAGES:
            results.append("NOT_PERMISSION_CONTROLLER")
            continue
        # The exact simple class name may be used only to choose a known
        # category. We never output it or infer which permission is asked.
        simple=cls.rsplit(".",1)[-1]
        result=TYPES.get(simple,"OTHER_PERMISSION_CONTROLLER_UI")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,100}",simple):
            result="UNKNOWN"
        results.append(result)
    unique=set(results)
    answer=next(iter(unique)) if len(unique)==1 else "AMBIGUOUS"
    if answer not in VALID_CATEGORIES:raise ValueError("P214_BAD_ENUM")
    return answer

def compare(early,late):
    if early==late and early.endswith("_UI_HINT"):
        return "SAME_UI_NAME_HINT_BOTH_INSTANTS"
    if early==late and early=="OTHER_PERMISSION_CONTROLLER_UI":
        return "SAME_UNRECOGNIZED_CONTROLLER_UI"
    if early==late and early=="NOT_PERMISSION_CONTROLLER":
        return "NO_CONTROLLER_AT_BOTH_INSTANTS"
    if "UNKNOWN" in (early,late) or "AMBIGUOUS" in (early,late):
        return "INSUFFICIENT_CLASS_EVIDENCE"
    return "UI_CLASS_CATEGORY_DIFFERS_OR_UNAVAILABLE"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--early-activities",required=True)
    ap.add_argument("--late-activities",required=True)
    args=ap.parse_args()
    try:
        early=classify(limited(args.early_activities))
        late=classify(limited(args.late_activities))
        relation=compare(early,late)
    except (ValueError,OSError):
        print("P214_CLASSIFICATION=DENY_UNRELIABLE_INPUT",file=sys.stderr)
        return 2
    print("P214_EARLY_PERMISSION_UI_CLASS_HINT="+early)
    print("P214_LATE_PERMISSION_UI_CLASS_HINT="+late)
    print("P214_PERMISSION_UI_CLASS_RELATION="+relation)
    print("P214_CLASS_NAME_ONLY_NOT_ACTUAL_PERMISSION_REQUEST=YES")
    print("P214_PERMISSION_NAME_OR_ARGUMENTS_EXPOSED=NO")
    print("P214_NO_USER_PERMISSION_AUTO_GRANT_OR_TAP=YES")
    print("P214_RAW_COMPONENT_OR_DUMPSYS_EXPOSED=NO")
    print("P214_ENGINE_PC3912_CAUSALITY=NOT_ATTESTED")
    print("P214_ORIGINAL_APK_AND_USER_PHONE_MODIFIED=NO")
    print("P214_RELEASE_V139=STRUCTURAL_BLOCKED")
    print("P214_PERMISSION_CLASS_HINT_AUDIT=PASS")
    return 0

if __name__=="__main__":
    sys.exit(main())
