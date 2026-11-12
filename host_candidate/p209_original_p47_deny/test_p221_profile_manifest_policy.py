#!/usr/bin/env python3
"""P221 synthetic in-memory manifest policy tests; no app or real device."""
import unittest
from xml.etree import ElementTree as ET
from audit_signed_node_bootstrap import Denied
from p221_profile_manifest_policy import manifest_policy,ANDROID

def sample(debug=None,shell=None,enabled=None,profile=False,package="com.dsh.android"):
    root=ET.Element("manifest",{"package":package})
    app=ET.SubElement(root,"application")
    if debug is not None:app.set(ANDROID+"debuggable",debug)
    if profile:
        child=ET.SubElement(app,"profileable")
        if shell is not None:child.set(ANDROID+"shell",shell)
        if enabled is not None:child.set(ANDROID+"enabled",enabled)
    return root

class Tests(unittest.TestCase):
    def test_absent_profileable_fails_closed(self):
        self.assertFalse(manifest_policy(sample())["eligible"])
    def test_debuggable_allows_tracing(self):
        self.assertTrue(manifest_policy(sample(debug="true"))["eligible"])
    def test_explicit_shell_true_allows_tracing(self):
        self.assertTrue(manifest_policy(sample(profile=True,shell="true"))["eligible"])
    def test_explicit_shell_false_denied(self):
        self.assertFalse(manifest_policy(sample(profile=True,shell="false"))["eligible"])
    def test_enabled_false_overrides_shell(self):
        self.assertFalse(manifest_policy(sample(profile=True,shell="true",enabled="false"))["eligible"])
    def test_enabled_false_overrides_debug(self):
        self.assertFalse(manifest_policy(sample(debug="true",profile=True,enabled="false"))["eligible"])
    def test_missing_shell_flag_denied(self):
        self.assertFalse(manifest_policy(sample(profile=True))["eligible"])
    def test_literal_one_true(self):
        self.assertTrue(manifest_policy(sample(profile=True,shell="1"))["eligible"])
    def test_literal_zero_false(self):
        self.assertFalse(manifest_policy(sample(debug="0"))["eligible"])
    def test_unknown_bool_denied(self):
        with self.assertRaises(Denied):manifest_policy(sample(debug="@7f010000"))
    def test_wrong_package_denied(self):
        with self.assertRaises(Denied):manifest_policy(sample(package="other.app"))
    def test_no_application_denied(self):
        x=sample();x.remove(x.find("application"))
        with self.assertRaises(Denied):manifest_policy(x)
    def test_duplicate_application_denied(self):
        x=sample();ET.SubElement(x,"application")
        with self.assertRaises(Denied):manifest_policy(x)
    def test_duplicate_profileable_denied(self):
        x=sample(profile=True);ET.SubElement(x.find("application"),"profileable")
        with self.assertRaises(Denied):manifest_policy(x)
    def test_enabled_true_without_shell_is_not_allowed(self):
        self.assertFalse(manifest_policy(sample(profile=True,enabled="true"))["eligible"])

if __name__=="__main__":
    unittest.main(verbosity=2)
