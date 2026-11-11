#!/usr/bin/env python3
"""P213 fail-closed synthetic external-family classification tests."""
import unittest
from p212_activity_transition import RESUMED_RE, FOCUS_RE
from p213_external_component_family import classify_family,interpret

def resumed(pkg,cls):
    return ("mResumedActivity: ActivityRecord{u0 "+pkg+"/"+cls+" t10}")

class ClassificationTests(unittest.TestCase):
    def test_launcher_main_android35(self):
        self.assertEqual(classify_family(resumed("com.android.launcher3",".Launcher"),
                                         RESUMED_RE),"LAUNCHER")
    def test_launcher_pixel_variant(self):
        self.assertEqual(classify_family(resumed(
            "com.google.android.apps.nexuslauncher",".NexusLauncherActivity"),
            RESUMED_RE),"LAUNCHER")
    def test_system_ui(self):
        self.assertEqual(classify_family(resumed("com.android.systemui",
                          ".keyguard.KeyguardPresentation"),RESUMED_RE),
                         "SYSTEM_UI")
    def test_android_permission_controller(self):
        self.assertEqual(classify_family(resumed("com.android.permissioncontroller",
                          ".permission.ui.GrantPermissionsActivity"),RESUMED_RE),
                         "PERMISSION_CONTROLLER")
    def test_google_permission_controller(self):
        self.assertEqual(classify_family(resumed("com.google.android.permissioncontroller",
                          ".permission.ui.GrantPermissionsActivity"),RESUMED_RE),
                         "PERMISSION_CONTROLLER")
    def test_settings(self):
        self.assertEqual(classify_family(resumed("com.android.settings",".Settings"),
                                         RESUMED_RE),"SETTINGS")
    def test_unknown_external_name_never_printed(self):
        secret="com.private.account_abc.privatecompany"
        out=classify_family(resumed(secret,".AccountPage"),RESUMED_RE)
        self.assertEqual(out,"OTHER_EXTERNAL")
        self.assertNotIn("account_abc",out)
    def test_original_application_is_not_external(self):
        self.assertEqual(classify_family(resumed("com.dsh.android",".MainActivity"),
                                         RESUMED_RE),"SAME_APPLICATION")
    def test_other_original_application_activity(self):
        self.assertEqual(classify_family(resumed("com.dsh.android",".LoginActivity"),
                                         RESUMED_RE),"SAME_APPLICATION")
    def test_null_not_launcher(self):
        self.assertEqual(classify_family("mResumedActivity=null",RESUMED_RE),
                         "NO_TARGET")
    def test_missing_category_unknown(self):
        self.assertEqual(classify_family("no available marker",RESUMED_RE),
                         "UNKNOWN")
    def test_two_discordant_component_rows_fail_closed(self):
        txt=resumed("com.android.launcher3",".Launcher")+"\n"+resumed(
            "com.android.systemui",".OtherActivity")
        self.assertEqual(classify_family(txt,RESUMED_RE),"AMBIGUOUS")
    def test_multiple_components_single_line_not_guessed(self):
        txt=resumed("com.android.launcher3",".Launcher") + " com.android.settings/.Settings"
        self.assertEqual(classify_family(txt,RESUMED_RE),"UNKNOWN")
    def test_strict_marker_not_any_component_mention(self):
        txt="com.android.launcher3/.Launcher (NOT a current resumed marker)"
        self.assertEqual(classify_family(txt,RESUMED_RE),"UNKNOWN")
    def test_focused_component_safely_classified(self):
        txt="mCurrentFocus=Window{a u0 com.android.launcher3/.Launcher}"
        self.assertEqual(classify_family(txt,FOCUS_RE),"LAUNCHER")
    def test_resumed_same_external_family_both(self):
        self.assertEqual(interpret(("LAUNCHER","UNKNOWN"),
                                   ("LAUNCHER","UNKNOWN")),
                         "SAME_EXTERNAL_FAMILY_AT_BOTH_INSTANTS")
    def test_unknown_second_not_called_stable(self):
        self.assertEqual(interpret(("LAUNCHER","UNKNOWN"),
                                   ("UNKNOWN","UNKNOWN")),
                         "INSUFFICIENT_EXTERNAL_CLASSIFICATION")
    def test_change_between_external_families(self):
        self.assertEqual(interpret(("LAUNCHER","UNKNOWN"),
                                   ("SYSTEM_UI","UNKNOWN")),
                         "FAMILY_CHANGED_BETWEEN_SNAPSHOTS")
    def test_application_displaced_by_external(self):
        self.assertEqual(interpret(("SAME_APPLICATION","UNKNOWN"),
                                   ("LAUNCHER","UNKNOWN")),
                         "APPLICATION_TO_NONAPPLICATION_BETWEEN_SNAPSHOTS")

if __name__=="__main__":unittest.main(verbosity=2)
