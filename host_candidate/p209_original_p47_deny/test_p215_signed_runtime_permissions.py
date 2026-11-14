#!/usr/bin/env python3
"""P215 fail-closed synthetic cases: manifest declared != runtime requested."""
import unittest
from collections import Counter
from audit_signed_node_bootstrap import Denied
from p215_signed_runtime_permissions import (
    class_call,permission_kind,label_caller,label_method,
    permission_group,manifest_summary,inventory_sites,APP,
)
class Ins:
    def __init__(self,op,out):self.op,self.out=op,out
    def get_name(self):return self.op
    def get_output(self):return self.out
class Method:
    def __init__(self,name,rows,code=True):
        self.name,self.rows,self.code=name,rows,code
    def get_name(self):return self.name
    def get_code(self):return object() if self.code else None
    def get_instructions_idx(self):return self.rows
class Cls:
    def __init__(self,name,methods):self.name,self.methods=name,methods
    def get_name(self):return self.name
    def get_methods(self):return self.methods
class Dex:
    def __init__(self,classes):self.classes=classes
    def get_classes(self):return self.classes

COMPAT="Landroidx/core/app/ActivityCompat;"
ACT="Landroid/app/Activity;"
REF=COMPAT+"->requestPermissions(Landroid/app/Activity;[Ljava/lang/String;I)V"
class PermissionSourceTests(unittest.TestCase):
    def test_true_direct_request_is_owner_and_method(self):
        self.assertEqual(class_call(Ins("invoke-static","v1, "+REF)),
                         (COMPAT,"requestPermissions"))
    def test_descriptor_only_request_is_not_direct_owner(self):
        i=Ins("invoke-virtual","v1, Lcom/example/Helper;->pass("+COMPAT+")V")
        self.assertEqual(class_call(i),("Lcom/example/Helper;","pass"))
        self.assertIsNone(permission_kind(*class_call(i)))
    def test_const_string_does_not_count_invoke(self):
        self.assertIsNone(class_call(Ins("const-string",REF)))
    def test_activity_permission_request(self):
        self.assertEqual(permission_kind(ACT,"requestPermissions"),
                         "DIRECT_REQUEST_API")
    def test_fragment_permission_request(self):
        self.assertEqual(permission_kind("Landroidx/fragment/app/Fragment;",
                                         "requestPermissions"),"DIRECT_REQUEST_API")
    def test_androidx_compat(self):
        self.assertEqual(permission_kind(COMPAT,"requestPermissions"),
                         "DIRECT_REQUEST_API")
    def test_library_lookalike_not_permission_request(self):
        self.assertIsNone(permission_kind("Lcom/malicious/ActivityCompat;",
                                          "requestPermissions"))
    def test_generic_activity_result_launch_not_request(self):
        self.assertEqual(permission_kind(
            "Landroidx/activity/result/ActivityResultLauncher;","launch"),
            "GENERIC_ACTIVITY_RESULT_LAUNCH")
        self.assertIsNone(permission_kind(ACT,"launch"))
    def test_activity_result_registration_not_request(self):
        self.assertEqual(permission_kind(
            "Landroidx/activity/ComponentActivity;","registerForActivityResult"),
            "GENERIC_ACTIVITY_RESULT_REGISTRATION")
    def test_request_with_wrong_owner_not_grant(self):
        self.assertIsNone(permission_kind("Landroid/widget/Button;",
                                          "requestPermissions"))
    def test_known_main_label(self):
        self.assertEqual(label_caller(APP+"MainActivity;"),"MAIN_ACTIVITY")
        self.assertEqual(label_caller(APP+"MainActivity$bootEngine$1;"),
                         "MAIN_BOOT_COROUTINE")
    def test_original_other_no_sensitive_class_echo(self):
        label=label_caller(APP+"account/PrivateKeySecret;")
        self.assertEqual(label,"ORIGINAL_APP_OTHER")
        self.assertEqual(label_method("getAuthToken"),"OTHER_METHOD")
    def test_original_nonapp_library_class(self):
        self.assertEqual(label_caller("Landroidx/core/app/ActivityCompat;"),
                         "BUNDLED_LIBRARY_OTHER")
    def test_declared_permissions_are_aggregated(self):
        counts=manifest_summary(["android.permission.POST_NOTIFICATIONS",
             "android.permission.READ_MEDIA_IMAGES",
             "android.permission.ACCESS_FINE_LOCATION",
             "android.permission.CAMERA",
             "android.permission.RECORD_AUDIO",
             "android.permission.BLUETOOTH_SCAN",
             "com.example.private.ACCESS_SECRET"])
        self.assertEqual(counts,Counter({"CAMERA_MIC":2,"NOTIFICATION":1,
            "STORAGE_MEDIA":1,"LOCATION":1,"NEARBY":1,"OTHER":1}))
    def test_invalid_manifest_non_string_refused(self):
        with self.assertRaises(Denied):permission_group(None)
    def test_manifest_too_large_refused(self):
        with self.assertRaises(Denied):manifest_summary(["a"]*257)
    def test_synthetic_real_direct_owner_site_count(self):
        fake=Method("onCreate",[(232,Ins("invoke-static","v1, "+REF)),
            (238,Ins("const-string","v1, "+REF))])
        d=Dex([Cls(APP+"MainActivity;",[fake])])
        sites,counts,method_count=inventory_sites([("classes.dex",d)])
        self.assertEqual(method_count,1)
        self.assertEqual(sites,[("classes.dex","MAIN_ACTIVITY","onCreate",
                                  232,"DIRECT_REQUEST_API")])
        self.assertEqual(counts[("MAIN_ACTIVITY","DIRECT_REQUEST_API")],1)
    def test_noncode_method_not_scanned(self):
        d=Dex([Cls(APP+"MainActivity;",[Method("nativeMethod",[],False),
            Method("onCreate",[(0,Ins("return-void",""))])])])
        sites,_,method_count=inventory_sites([("classes.dex",d)])
        self.assertEqual(sites,[])
        self.assertEqual(method_count,1)
    def test_library_compat_request_not_original_app(self):
        d=Dex([Cls(COMPAT,[Method("invoke",[(0,Ins("invoke-virtual",
            "v0, "+ACT+"->requestPermissions([Ljava/lang/String;I)V"))])])])
        sites,_,_=inventory_sites([("classes2.dex",d)])
        self.assertEqual(sites[0][1],"BUNDLED_LIBRARY_OTHER")
    def test_no_sites_does_not_mean_no_permission_runtime(self):
        d=Dex([Cls(APP+"MainActivity;",[Method("onCreate",[
            (0,Ins("invoke-virtual","v1, Lcom/example/Helper;->request()V"))])])])
        sites,_,_=inventory_sites([("classes.dex",d)])
        self.assertEqual(sites,[])

if __name__=="__main__":unittest.main(verbosity=2)
