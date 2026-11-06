#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

location = Path(__file__).with_name("audit_signed_v138.py")
spec = importlib.util.spec_from_file_location("b0_audit", location)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class StrictNegativeTests(unittest.TestCase):
    def test_unrelated_cookie_method_not_counted(self):
        self.assertIsNone(audit.api_kind("Lacme/Other;->setCookie("))
    def test_exact_suffix(self):
        self.assertEqual("WEBVIEW_SUFFIX",audit.api_kind(
            "v0,Landroid/webkit/WebView;->setDataDirectorySuffix(Ljava/lang/String;)V"))
    def test_process_global_not_webview_direct(self):
        self.assertEqual("GLOBAL_CONFIG_SUFFIX",audit.api_kind(
            "Landroidx/webkit/ProcessGlobalConfig;->setDataDirectorySuffix("
            "Landroid/content/Context;Ljava/lang/String;)V"))
    def test_third_party_cookie_method(self):
        self.assertEqual("THIRD_PARTY_COOKIE",audit.api_kind(
            "Landroid/webkit/CookieManager;->setAcceptThirdPartyCookies("
            "Landroid/webkit/WebView;Z)V"))
    def test_string_mentions_do_not_count(self):
        totals, n = audit.count_invocations([
            ("Lcom/dsh/android/browser/AiBrowserView;","const-string",
             "Landroid/webkit/CookieManager;->getInstance(")])
        self.assertEqual(0,totals["COOKIE_INSTANCE"])
        self.assertEqual(0,n)
    def test_browser_scope_not_all_app_cookie_calls(self):
        totals,n = audit.count_invocations([
            ("Lcom/dsh/android/MainActivity;","invoke-static",
             "Landroid/webkit/CookieManager;->getInstance("),
            ("Lcom/dsh/android/browser/AiBrowserView;","invoke-static",
             "Landroid/webkit/CookieManager;->getInstance(")])
        self.assertEqual(2,totals["COOKIE_INSTANCE"])
        self.assertEqual(1,n)
    def test_signed_mailbox_exact_literals(self):
        self.assertEqual({"browser-cmd.json": True, "browser-result.json": True},
                         audit.exact_mailbox_literals(["browser-cmd.json",
                             "browser-result.json", "unrelated"]))
    def test_mailbox_substrings_do_not_count(self):
        values=["prefix-browser-cmd.json", "browser-result.json.backup"]
        self.assertEqual({"browser-cmd.json": False, "browser-result.json": False},
                         audit.exact_mailbox_literals(values))
    def test_one_missing_mailbox_literal_is_not_inferred(self):
        result=audit.exact_mailbox_literals(["browser-cmd.json"])
        self.assertTrue(result["browser-cmd.json"])
        self.assertFalse(result["browser-result.json"])
    def test_missing_original_fails_closed(self):
        with self.assertRaisesRegex(ValueError,"B0_DENY_ORIGINAL_MISSING"):
            audit.analyze("/never_exists/DSH-v138.apk")
    def test_suffix_presence_is_not_vm_evidence(self):
        totals,_ = audit.count_invocations([
            ("Lcom/dsh/android/DshApplication;","invoke-static",
             "Landroid/webkit/WebView;->setDataDirectorySuffix(")])
        self.assertEqual(1,totals["WEBVIEW_SUFFIX"])
        self.assertNotIn("VIRTUAL_MACHINE",totals)

if __name__ == "__main__":
    unittest.main(verbosity=2)
