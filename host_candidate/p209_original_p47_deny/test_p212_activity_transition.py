#!/usr/bin/env python3
"""P212 synthetic negatives: no raw Android identities, no inferred transitions."""
import unittest
from p212_activity_transition import (
    frame, signal, transition, RESUMED_RE, FOCUS_RE,
)

MAIN="topResumedActivity=ActivityRecord{z u0 com.dsh.android/.MainActivity t42}"
MAIN_FULL="mResumedActivity: com.dsh.android/com.dsh.android.MainActivity"
OTHER_APP="mResumedActivity: com.dsh.android/.LoginActivity"
OTHER_PACKAGE="mResumedActivity: com.android.launcher3/.Launcher"
FOCUS_MAIN="mCurrentFocus=Window{e u0 com.dsh.android/com.dsh.android.MainActivity}"
FOCUS_OTHER="mFocusedApp=ActivityRecord{e u0 com.other.app/.Prompt}"
PID="12345"

class TransitionNegatives(unittest.TestCase):
    def test_main_shorthand_resumed(self):
        self.assertEqual(signal(MAIN,RESUMED_RE),"MAIN")
    def test_main_fully_qualified_resumed(self):
        self.assertEqual(signal(MAIN_FULL,RESUMED_RE),"MAIN")
    def test_other_same_app_not_main(self):
        self.assertEqual(signal(OTHER_APP,RESUMED_RE),"SAME_PACKAGE_OTHER")
    def test_other_package_not_same_app(self):
        self.assertEqual(signal(OTHER_PACKAGE,RESUMED_RE),"EXTERNAL_COMPONENT")
    def test_focus_app_main(self):
        self.assertEqual(signal(FOCUS_MAIN,FOCUS_RE),"MAIN")
    def test_focus_other_package(self):
        self.assertEqual(signal(FOCUS_OTHER,FOCUS_RE),"EXTERNAL_COMPONENT")
    def test_null_and_missing_distinguished(self):
        self.assertEqual(signal("mResumedActivity: null",RESUMED_RE),"NO_TARGET")
        self.assertEqual(signal("unrelated",RESUMED_RE),"UNKNOWN")
    def test_no_implicit_component_from_package_text(self):
        self.assertEqual(signal("mResumedActivity: com.dsh.android.MainActivity",
                                RESUMED_RE),"UNKNOWN")
    def test_mixed_resumed_markers_ambiguous(self):
        self.assertEqual(signal(MAIN+"\n"+OTHER_APP,RESUMED_RE),"AMBIGUOUS")
    def test_many_markers_fail_closed(self):
        self.assertEqual(signal("\n".join([MAIN]*13),RESUMED_RE),"AMBIGUOUS")
    def test_app_pid_not_stable_deny(self):
        self.assertEqual(frame(PID,"",MAIN,FOCUS_MAIN)[0],"GONE")
        self.assertEqual(frame(PID,"44444",MAIN,FOCUS_MAIN)[0],
                         "PID_DRIFT_OR_MULTIPLE")
        self.assertEqual(frame(PID,"12345 12346",MAIN,FOCUS_MAIN)[0],
                         "PID_DRIFT_OR_MULTIPLE")
    def test_bad_host_pid_rejected(self):
        for value in ("abc","1","123;echo","12 45","123\n456"):
            with self.assertRaises(ValueError):
                frame(value,value,MAIN,FOCUS_MAIN)
    def test_main_left_foreground(self):
        e=frame(PID,PID,MAIN,FOCUS_MAIN)
        l=frame(PID,PID,OTHER_APP,FOCUS_OTHER)
        self.assertEqual(transition(e,l),"MAIN_WAS_RESUMED_THEN_NOT")
    def test_main_gained_foreground(self):
        e=frame(PID,PID,OTHER_PACKAGE,FOCUS_OTHER)
        l=frame(PID,PID,MAIN,FOCUS_MAIN)
        self.assertEqual(transition(e,l),"MAIN_BECAME_RESUMED")
    def test_main_still_front(self):
        x=frame(PID,PID,MAIN,FOCUS_MAIN)
        self.assertEqual(transition(x,x),"MAIN_RESUMED_BOTH")
    def test_process_drift_refuses_transition(self):
        e=frame(PID,"44444",MAIN,FOCUS_MAIN)
        l=frame(PID,PID,OTHER_APP,FOCUS_OTHER)
        self.assertEqual(transition(e,l),"NO_STABLE_PROCESS")
    def test_unknown_late_not_called_foreground_loss(self):
        e=frame(PID,PID,MAIN,FOCUS_MAIN)
        l=frame(PID,PID,"unrelated","unrelated")
        self.assertEqual(transition(e,l),"INSUFFICIENT_RESUMED_EVIDENCE")
    def test_foreign_both_no_assumed_main(self):
        e=frame(PID,PID,OTHER_APP,FOCUS_OTHER)
        l=frame(PID,PID,OTHER_PACKAGE,FOCUS_OTHER)
        self.assertEqual(transition(e,l),"MAIN_NOT_RESUMED_IN_EITHER_SNAPSHOT")

if __name__=="__main__":unittest.main(verbosity=2)
