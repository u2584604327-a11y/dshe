#!/usr/bin/env python3
"""P224 negative/synthetic event-log sanitizer tests; no real logcat data."""
import unittest
from p224_event_hint_sanitize import classify,TAGS
class TestP224(unittest.TestCase):
    def sample(self,tag="am_proc_died",pid="12345",name="com.dsh.android"):
        return ("11-12 00:00:00.123 1000 1000 I "+tag+": [0,"+pid+",10234,"+name+",test]\n").encode()
    def test_death_hint(self):
        c,d,n=classify(self.sample(),"12345","23456")
        self.assertEqual((c["am_proc_died"],d,n),(1,1,0))
    def test_new_pid_start(self):
        c,d,n=classify(self.sample(tag="am_proc_start",pid="23456"),"12345","23456")
        self.assertEqual((c["am_proc_start"],d,n),(1,0,1))
    def test_other_package_excluded(self):
        self.assertEqual(classify(self.sample(name="com.other.app"),"12345","23456")[0]["am_proc_died"],0)
    def test_similar_package_excluded(self):
        self.assertEqual(classify(self.sample(name="com.dsh.android.evil"),"12345","23456")[0]["am_proc_died"],0)
    def test_crash_hint(self):
        self.assertEqual(classify(self.sample(tag="am_crash"),"12345","23456")[0]["am_crash"],1)
    def test_unknown_event_ignored(self):
        self.assertTrue(all(v==0 for v in classify(self.sample(tag="unknown_tag"),"12345","23456")[0].values()))
    def test_invalid_old_pid_denied(self):
        with self.assertRaises(ValueError):classify(self.sample(),"1234 567","23456")
    def test_invalid_new_pid_denied(self):
        with self.assertRaises(ValueError):classify(self.sample(),"12345","abc")
    def test_large_log_denied(self):
        with self.assertRaises(ValueError):classify(b"X"*300000,"12345","23456")
    def test_partial_pid_not_matched(self):
        self.assertEqual(classify(self.sample(pid="123456"),"12345","23456")[1],0)
    def test_empty_input_is_unknown_not_crash(self):
        self.assertTrue(all(v==0 for v in classify(b"","12345","23456")[0].values()))
if __name__=="__main__":unittest.main(verbosity=2)
