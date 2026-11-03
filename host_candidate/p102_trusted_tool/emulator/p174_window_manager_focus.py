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
# P180: mFocusedApp=LAB is NOT proof of a focused LAB window. The WMS
# mCurrentFocus window may be owned by many distinct SystemUI components.
# Report only a fixed public category, never raw Window{...} labels, app data,
# user-visible text, task/window identifiers, paths or another app's identity.
# These categories are read-only diagnostics and NEVER authorize consent.
def focused_window_kind(content):
    if len(content) > MAX_BYTES:
        return "OVERSIZE"
    current = re.findall(r"(?m)^[ \\t]*mCurrentFocus[ \\t]*=[ \\t]*(.*)$", content)
    if not current:
        return "UNAVAILABLE"
    value = current[-1]
    group = classify(value)
    if group == "KEYGUARD":
        return "KEYGUARD"
    if group != "SYSTEMUI":
        return "NOT_SYSTEMUI"
    v = value.lower()
    # Order by specificity, not visibility or priority. Unknown SystemUI
    # windows remain unresolved; no fallback focus synthesis is permitted.
    for name, hints in (
        ("NOTIFICATION_SHADE", ("notificationshade", "notificationpanel", "quicksettings")),
        ("GLOBAL_ACTIONS", ("globalactions", "powerdialog")),
        ("VOLUME_DIALOG", ("volumedialog", "volumeoverlay")),
        ("STATUS_BAR", ("statusbar", "status_bar")),
        ("NAVIGATION_BAR", ("navigationbar", "navigation_bar")),
        ("SCREEN_DECOR", ("screendecor", "privacyindicator")),
        ("RECENTS", ("recents", "overviewpanel")),
    ):
        if any(word in v for word in hints):
            return name
    return "OTHER_SYSTEMUI"

def main():
    data = sys.stdin.buffer.read(MAX_BYTES + 1)
    try:
        snapshot = data.decode("utf-8", errors="replace")
        window, activity, lockscreen = summarize(snapshot)
        detail = focused_window_kind(snapshot)
    except Exception:
        window, activity, lockscreen = "UNAVAILABLE", "UNAVAILABLE", "UNKNOWN"
        detail = "UNAVAILABLE"
    print("P180_WM_FOCUSED_WINDOW_KIND=" + detail)
    print("P174_WM_CURRENT_FOCUS_CATEGORY=" + window)
    print("P174_WM_FOCUSED_APP_CATEGORY=" + activity)
    print("P174_WM_KEYGUARD_SHOWING=" + lockscreen)
    print("P174_WINDOW_MANAGER_IS_READ_ONLY_NO_APPROVAL=YES")
if __name__ == "__main__": main()
