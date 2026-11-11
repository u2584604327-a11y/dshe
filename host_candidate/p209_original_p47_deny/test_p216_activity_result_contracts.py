#!/usr/bin/env python3
"""P216 safety tests: distinguish permission-specific contracts from generic launches."""
import unittest
from audit_signed_node_bootstrap import Denied
from p216_activity_result_contracts import (
    event_for,launcher_fields,extract_events,field_hints,owner_class,
    MAIN,LAUNCHER,CONTRACT_ROOT,
)
class I:
    def __init__(self,name,out):self.name,self.out=name,out
    def get_name(self):return self.name
    def get_output(self):return self.out
class Field:
    def __init__(self,name,desc):self.name,self.desc=name,desc
    def get_name(self):return self.name
    def get_descriptor(self):return self.desc
class Meth:
    def __init__(self,name,rows,code=True):self.name,self.rows,self.code=name,rows,code
    def get_name(self):return self.name
    def get_code(self):return object() if self.code else None
    def get_instructions_idx(self):return self.rows
class Cls:
    def __init__(self,name,methods,fields=()):
        self.name,self.methods,self.fields=name,methods,fields
    def get_name(self):return self.name
    def get_methods(self):return self.methods
    def get_fields(self):return self.fields
class Dex:
    def __init__(self,classes):self.classes=classes
    def get_classes(self):return self.classes

PERM="new-instance v1, "+CONTRACT_ROOT+"RequestPermission;"
MULTI="new-instance v2, "+CONTRACT_ROOT+"RequestMultiplePermissions;"
OTHER="new-instance v3, "+CONTRACT_ROOT+"GetContent;"
REG=("v0, v1, Landroidx/activity/ComponentActivity;->"
     "registerForActivityResult(Landroidx/activity/result/contract/ActivityResultContract;"
     "Landroidx/activity/result/ActivityResultCallback;)"
     "Landroidx/activity/result/ActivityResultLauncher;")
LAUNCH="v1, Landroidx/activity/result/ActivityResultLauncher;->launch(Ljava/lang/Object;)V"
FIELD_NAME="permissionsLauncher"
GET="v1, v0, "+MAIN+"->"+FIELD_NAME+":"+LAUNCHER
SET="v1, v0, "+MAIN+"->"+FIELD_NAME+":"+LAUNCHER
FIELDS=[Field(FIELD_NAME,LAUNCHER)]
class ContractsTests(unittest.TestCase):
    def test_runtime_one_permission_contract_new(self):
        self.assertEqual(event_for(I("new-instance",PERM),{}),
                         ("PERMISSION_CONTRACT_NEW","REQUEST_ONE"))
    def test_runtime_multiple_contract_new(self):
        self.assertEqual(event_for(I("new-instance",MULTI),{}),
                         ("PERMISSION_CONTRACT_NEW","REQUEST_MULTIPLE"))
    def test_get_content_is_not_permission(self):
        self.assertEqual(event_for(I("new-instance",OTHER),{}),
                         ("OTHER_CONTRACT_NEW","GET_CONTENT"))
    def test_library_generic_launch_not_request(self):
        self.assertEqual(event_for(I("invoke-virtual",LAUNCH),{}),
                         ("GENERIC_LAUNCH","LAUNCH"))
    def test_explicit_contract_constructor_invoke(self):
        s="v1, "+CONTRACT_ROOT+"RequestPermission;-><init>()V"
        self.assertEqual(event_for(I("invoke-direct",s),{}),
                         ("CONTRACT_CONSTRUCTOR_INVOKE","REQUEST_ONE"))
    def test_register_is_not_self_proof_of_permission(self):
        self.assertEqual(event_for(I("invoke-virtual",REG),{}),
                         ("ACTIVITY_RESULT_REGISTER","REGISTRATION"))
    def test_literal_string_never_counts_as_constructor(self):
        self.assertIsNone(event_for(I("const-string",PERM),{}))
    def test_other_package_fake_contract_not_permission(self):
        self.assertIsNone(event_for(I("new-instance",
                        "new-instance v0, Lcom/example/RequestPermission;"),{}))
    def test_launcher_field_get(self):
        self.assertEqual(event_for(I("iget-object",GET),{FIELD_NAME:1}),
                         ("LAUNCHER_FIELD_GET",1))
    def test_launcher_field_set(self):
        self.assertEqual(event_for(I("iput-object",SET),{FIELD_NAME:1}),
                         ("LAUNCHER_FIELD_SET",1))
    def test_wrong_field_name_not_assumed(self):
        self.assertIsNone(event_for(I("iget-object",GET),
                                     {"anotherLauncher":2}))
    def test_actual_launcher_field_inventory(self):
        c=Cls(MAIN,[],[Field("z",LAUNCHER),Field("a",LAUNCHER),
                       Field("other","Ljava/lang/String;")])
        self.assertEqual(launcher_fields(c),{"a":1,"z":2})
    def test_duplicate_launcher_fields_refused(self):
        c=Cls(MAIN,[],[Field("z",LAUNCHER),Field("z",LAUNCHER)])
        with self.assertRaises(Denied):launcher_fields(c)
    def test_scope_main_and_nested_distinguished(self):
        self.assertEqual(owner_class(MAIN),"MAIN_ACTIVITY")
        self.assertEqual(owner_class("Lcom/dsh/android/MainActivity$onCreate$1;"),
                         "MAIN_NESTED")
        self.assertEqual(owner_class("Landroidx/activity/ComponentActivity;"),
                         "BUNDLED_LIBRARY")
    def test_static_same_method_field_hint_only(self):
        rows=[(0,I("new-instance",PERM)),
              (4,I("invoke-virtual",REG)),
              (12,I("iput-object",SET)),
              (20,I("iget-object",GET)),
              (24,I("invoke-virtual",LAUNCH))]
        d=Dex([Cls(MAIN,[Meth("initPerm",rows)],FIELDS)])
        fields,events,launches,scanned=extract_events([("classes.dex",d)])
        self.assertEqual(fields,{FIELD_NAME:1})
        self.assertEqual(scanned,1)
        self.assertEqual(launches,[(24,(1,))])
        inferred,n=field_hints(events,launches)
        self.assertEqual((inferred,n),([1],1))
    def test_contract_without_registration_not_bound(self):
        d=Dex([Cls(MAIN,[Meth("initPerm",[
            (0,I("new-instance",PERM)),(12,I("iput-object",SET))]),
            Meth("send",[(0,I("iget-object",GET)),
                        (4,I("invoke-virtual",LAUNCH))])],FIELDS)])
        _,events,launches,_=extract_events([("classes.dex",d)])
        self.assertEqual(field_hints(events,launches),([],0))
    def test_not_assume_launcher_from_faraway_get(self):
        d=Dex([Cls(MAIN,[Meth("init",[(0,I("new-instance",PERM)),
            (4,I("invoke-virtual",REG)),(8,I("iput-object",SET))]),
            Meth("send",[(0,I("iget-object",GET)),
                         (100,I("invoke-virtual",LAUNCH))])],FIELDS)])
        _,events,launches,_=extract_events([("classes.dex",d)])
        self.assertEqual(launches,[(100,())])
        self.assertEqual(field_hints(events,launches),([1],0))
    def test_other_dex_other_app_not_main(self):
        d=Dex([Cls("Lcom/dsh/android/Other;",[Meth("send",[
            (4,I("invoke-virtual",LAUNCH))])])])
        fields,events,launches,scanned=extract_events([
            ("classes.dex",Dex([Cls(MAIN,[Meth("onCreate",[])],FIELDS)])),
            ("classes2.dex",d)])
        self.assertEqual(fields,{FIELD_NAME:1})
        self.assertEqual(launches,[])
        self.assertEqual(events[0][1],"OTHER_ORIGINAL_APP")
        self.assertEqual(scanned,2)
    def test_missing_main_class_fail_closed(self):
        with self.assertRaises(Denied):
            extract_events([("classes.dex",Dex([Cls("Lcom/other/Fake;",[])]))])
    def test_duplicate_main_class_fail_closed(self):
        with self.assertRaises(Denied):
            extract_events([("classes.dex",Dex([Cls(MAIN,[]),Cls(MAIN,[])]))])

if __name__=="__main__":unittest.main(verbosity=2)
