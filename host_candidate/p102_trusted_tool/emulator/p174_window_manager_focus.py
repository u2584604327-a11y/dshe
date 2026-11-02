#!/usr/bin/env python3
"""P174: private-data-safe guest WMS snapshot classification, only on failure."""
import re
import sys
MAX_BYTES = 4 * 1024 * 1024
LAB = "com.dsh.p102.trustedtoolprobe"
def classify(value):
    if not value or value.strip() in ("null", "None"): return "NONE"
    v = value.lower()
    if LAB in v: return "LAB"
    if "keyguard" in v or "dreamoverlay" in v: return "KEYGUARD"
    if "com.android.systemui" in v: return "SYSTEMUI"
    if "launcher" in v or "quickstep" in v: return "LAUNCHER"
    return "OTHER"
def summarize(content):
    if len(content) > MAX_BYTES: return ("OVERSIZE", "OVERSIZE", "UNKNOWN")
    current = re.findall(r"(?m)^[ \t]*mCurrentFocus[ \t]*=[ \t]*(.*)$", content)
    focused = re.findall(r"(?m)^[ \t]*mFocusedApp[ \t]*=[ \t]*(.*)$", content)
    showing = re.findall(r"(?mi)\b(?:mShowingLockscreen|mKeyguardShowing|isKeyguardShowing)[ \t]*=[ \t]*(true|false)\b", content)
    lockscreen = "UNKNOWN" if not showing else ("YES" if showing[-1].lower() == "true" else "NO")
    return (classify(current[-1]) if current else "UNAVAILABLE",
            classify(focused[-1]) if focused else "UNAVAILABLE",
            lockscreen)
def main():
    data = sys.stdin.buffer.read(MAX_BYTES + 1)
    try: window, activity, lockscreen = summarize(data.decode("utf-8", errors="replace"))
    except Exception: window, activity, lockscreen = "UNAVAILABLE", "UNAVAILABLE", "UNKNOWN"
    print("P174_WM_CURRENT_FOCUS_CATEGORY=" + window)
    print("P174_WM_FOCUSED_APP_CATEGORY=" + activity)
    print("P174_WM_KEYGUARD_SHOWING=" + lockscreen)
    print("P174_WINDOW_MANAGER_IS_READ_ONLY_NO_APPROVAL=YES")
if __name__ == "__main__": main()
