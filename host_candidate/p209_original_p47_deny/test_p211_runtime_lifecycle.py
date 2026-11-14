#!/usr/bin/env python3
"""P211 synthetic lifecycle observation tests; never touch a phone or emulator."""
import unittest
from p211_runtime_lifecycle import classify

PID="12345"
RESUMED="mResumedActivity: ActivityRecord{z u0 com.dsh.android/.MainActivity t42}"
WINDOW="mCurrentFocus=Window{a u0 com.dsh.android/com.dsh.android.MainActivity}"
OTHER="mCurrentFocus=Window{a u0 com.android.launcher3/.Launcher}"
class LifecycleTests(unittest.TestCase):
    def test_live_main_both_signals(self):
        self.assertEqual(classify(PID,PID,RESUMED,WINDOW),
                         ("YES","YES","YES","FOREGROUND_MAIN_AND_LIVE"))
    def test_missing_process_never_claim_main(self):
        self.assertEqual(classify(PID,"",RESUMED,WINDOW)[3],
                         "PROCESS_NOT_STABLE_OR_GONE")
    def test_different_pid_classified_drift(self):
        self.assertEqual(classify(PID,"23456",RESUMED,WINDOW)[0],
                         "DRIFT_OR_MULTIPLE")
    def test_multiple_pids_not_assumed(self):
        self.assertEqual(classify(PID,"12345 12346",RESUMED,WINDOW)[0],
                         "DRIFT_OR_MULTIPLE")
    def test_focus_not_main_but_resumed_main(self):
        self.assertEqual(classify(PID,PID,RESUMED,OTHER)[1:3],
                         ("YES","NO"))
    def test_no_resumed_line_unknown(self):
        self.assertEqual(classify(PID,PID,"mTask=unrelated",WINDOW)[1],
                         "UNKNOWN")
    def test_no_focus_line_unknown(self):
        self.assertEqual(classify(PID,PID,RESUMED,"unrelated")[2],
                         "UNKNOWN")
    def test_not_resumed_not_focused(self):
        v=classify(PID,PID,"mResumedActivity: com.android.launcher3",OTHER)
        self.assertEqual(v[1:3],("NO","NO"))
        self.assertEqual(v[3],"PROCESS_ALIVE_NOT_PROVEN_FOREGROUND")
    def test_main_text_without_resumed_tag_cannot_be_resumed(self):
        self.assertEqual(classify(PID,PID,
            "com.dsh.android.MainActivity",OTHER)[1],"UNKNOWN")
    def test_mixed_resumed_entries_never_simple_yes(self):
        v=classify(PID,PID,RESUMED+"\n"+"mResumedActivity: com.other.Main",WINDOW)
        self.assertEqual(v[1],"MIXED")
    def test_unbounded_resumed_lines_not_assumed(self):
        v=classify(PID,PID,"\n".join([RESUMED]*9),WINDOW)
        self.assertEqual(v[1],"AMBIGUOUS")
    def test_invalid_pid_refused(self):
        for x in ("abc","0","1;rm -rf","1 2","123\n45"):
            with self.assertRaises(ValueError):classify(x,x,RESUMED,WINDOW)
if __name__=="__main__":unittest.main(verbosity=2)
