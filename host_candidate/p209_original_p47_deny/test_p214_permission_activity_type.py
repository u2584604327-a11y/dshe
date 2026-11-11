#!/usr/bin/env python3
"""No APK/device: P214 synthetic UI-name classification negative tests."""
import unittest
from p214_permission_activity_type import classify,compare

def resumed(package,cls):
    return "mResumedActivity: ActivityRecord{u0 "+package+"/"+cls+" t42}"

PKG="com.android.permissioncontroller"
GPKG="com.google.android.permissioncontroller"
class HintTests(unittest.TestCase):
    def test_android_runtime_grant(self):
        self.assertEqual(classify(resumed(PKG,
            ".permission.ui.GrantPermissionsActivity")),"RUNTIME_GRANT_UI_HINT")
    def test_google_runtime_grant(self):
        self.assertEqual(classify(resumed(GPKG,
            ".permission.ui.GrantPermissionsActivity")),"RUNTIME_GRANT_UI_HINT")
    def test_review(self):
        self.assertEqual(classify(resumed(PKG,".ReviewPermissionsActivity")),"REVIEW_UI_HINT")
    def test_manage(self):
        self.assertEqual(classify(resumed(PKG,".ManagePermissionsActivity")),"MANAGE_UI_HINT")
    def test_app_permission(self):
        self.assertEqual(classify(resumed(PKG,".AppPermissionActivity")),"APP_PERMISSION_UI_HINT")
    def test_usage(self):
        self.assertEqual(classify(resumed(PKG,".PermissionUsageActivity")),"USAGE_UI_HINT")
    def test_management(self):
        self.assertEqual(classify(resumed(PKG,".ManageApplicationsActivity")),"MANAGEMENT_UI_HINT")
    def test_unrecognized_controller_cannot_infer_type(self):
        self.assertEqual(classify(resumed(PKG,".PrivateMysteryActivity")),
                         "OTHER_PERMISSION_CONTROLLER_UI")
    def test_other_package_with_spoofed_grant_name_is_not_controller(self):
        self.assertEqual(classify(resumed("com.malicious.test",
            ".GrantPermissionsActivity")),"NOT_PERMISSION_CONTROLLER")
    def test_similar_name_but_other_controller_package_not_trusted(self):
        self.assertEqual(classify(resumed("com.android.permissioncontroller.fake",
            ".GrantPermissionsActivity")),"NOT_PERMISSION_CONTROLLER")
    def test_empty_snapshot_is_no_resumed_component(self):
        self.assertEqual(classify("nothing"),"NO_RESUMED_COMPONENT")
    def test_null_snapshot_is_no_resumed_component(self):
        self.assertEqual(classify("mResumedActivity: null"),"NO_RESUMED_COMPONENT")
    def test_missing_class_not_guessed(self):
        self.assertEqual(classify("mResumedActivity: com.android.permissioncontroller"),
                         "UNKNOWN")
    def test_many_rows_ambiguous(self):
        self.assertEqual(classify("\n".join([resumed(PKG,".GrantPermissionsActivity")]*13)),
                         "AMBIGUOUS")
    def test_multiple_components_per_row_unknown(self):
        line=resumed(PKG,".GrantPermissionsActivity") + " com.malicious/.Other"
        self.assertEqual(classify(line),"UNKNOWN")
    def test_mixed_controller_categories_ambiguous(self):
        self.assertEqual(classify(resumed(PKG,".GrantPermissionsActivity")+"\n"+
            resumed(PKG,".ReviewPermissionsActivity")),"AMBIGUOUS")
    def test_names_with_secrets_are_not_echoed(self):
        text="private_credential_ABCDE"
        category=classify(resumed(PKG,".SecretActivity"+text))
        self.assertEqual(category,"OTHER_PERMISSION_CONTROLLER_UI")
        self.assertNotIn(text,category)
    def test_consistent_two_snapshots(self):
        self.assertEqual(compare("RUNTIME_GRANT_UI_HINT","RUNTIME_GRANT_UI_HINT"),
                         "SAME_UI_NAME_HINT_BOTH_INSTANTS")
    def test_unknown_class_both_snapshots_not_credible_grant(self):
        self.assertEqual(compare("OTHER_PERMISSION_CONTROLLER_UI",
                                 "OTHER_PERMISSION_CONTROLLER_UI"),
                         "SAME_UNRECOGNIZED_CONTROLLER_UI")
    def test_unknown_one_snapshot_insufficient(self):
        self.assertEqual(compare("UNKNOWN","RUNTIME_GRANT_UI_HINT"),
                         "INSUFFICIENT_CLASS_EVIDENCE")
    def test_grant_then_review_not_stable(self):
        self.assertEqual(compare("RUNTIME_GRANT_UI_HINT","REVIEW_UI_HINT"),
                         "UI_CLASS_CATEGORY_DIFFERS_OR_UNAVAILABLE")

if __name__=="__main__":unittest.main(verbosity=2)
