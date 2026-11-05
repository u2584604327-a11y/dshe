#!/usr/bin/env python3
"""P202 synthetic constructor-site tests only; no signed APK, no Android."""
import json
import unittest
from unittest.mock import patch
import audit_original_lambda_constructors as a

p=a.p201
ENGINE=p.ENGINE
MAIN="Lcom/dsh/android/MainActivity;"
def node(owner,name,desc="()V"):
    return p.key(owner,name,desc)
def ref(owner,name,desc="()V",op="invoke-virtual",pc=10):
    return (pc,op,"v0, "+owner+"->"+name+desc)
def fx():
    methods=[]
    for index,(tag,cls) in enumerate(a.TARGET_LAMBDAS.items()):
        methods.append((node(cls,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;"),
          [ref(ENGINE,"start",pc=100+index)]))
        parent=tag.lower()
        methods.append((node(MAIN,parent),
          [(20,"new-instance","v0, "+cls),
           ref(cls,"<init>","(Lkotlin/coroutines/Continuation;)V",
               "invoke-direct",30)]))
    methods.append((node(ENGINE,"probe$default"),[ref(ENGINE,"probeBoot",pc=77)]))
    methods.append((node(ENGINE,"preflight"),[ref(ENGINE,"runDumpConfig",pc=80),
                                            ref(ENGINE,"runDumpConfig",pc=81)]))
    methods.append((node(ENGINE,"rebuildEngine"),
                    [ref(ENGINE,"runDumpConfig",pc=82)]))
    methods.append((node(MAIN,"onClick"),
      [ref(MAIN,"boot",pc=91)]))
    methods.append((node(MAIN,"onResume"),
      [ref(MAIN,"auto_safe",pc=92)]))
    return methods

class TestP202(unittest.TestCase):
    def deny(self,code,f):
        with self.assertRaises(a.Blocked) as z:f()
        self.assertEqual(str(z.exception),"P202_DENY_"+code)
    def test_real_four_names_expected(self):
        self.assertEqual(sorted(a.TARGET_LAMBDAS),
                         ["AUTO_SAFE","BOOT","MANUAL_SAFE","OBSERVE"])
    def test_strict_four_lambda_methods(self):
        report=a.describe(fx())
        self.assertTrue(report["original_start_callsites_verified"])
        self.assertEqual(len(report["lambda_origins"]),4)
    def test_each_constructor_exact(self):
        q=a.describe(fx())
        self.assertEqual({k:v["constructor_site_count"] for k,v in
                          q["lambda_origins"].items()},
                         {"AUTO_SAFE":1,"BOOT":1,"MANUAL_SAFE":1,"OBSERVE":1})
    def test_each_allocation_count(self):
        q=a.describe(fx())
        self.assertEqual({k:v["allocation_site_count"] for k,v in
                          q["lambda_origins"].items()},
                         {"AUTO_SAFE":1,"BOOT":1,"MANUAL_SAFE":1,"OBSERVE":1})
    def test_actual_parent_symbols(self):
        q=a.describe(fx())
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_sources"][0]
             ["caller_symbol"],"com.dsh.android.MainActivity.boot")
    def test_not_a_real_ui_click(self):
        q=a.describe(fx())
        self.assertIs(q["real_android_button_tapped"],False)
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_sources"][0]
                         ["actual_event_executed"],"NOT_PROVEN")
    def test_no_coroutine_authority(self):
        q=a.describe(fx())
        self.assertFalse(q["real_os_owner_generation_attested"])
        self.assertFalse(q["p184_receipt_delivered_to_real_coroutine"])
        self.assertFalse(q["arm64_node_fd_http_ready"])
    def test_class_constructor_not_arbitrary_method(self):
        wrong="Lcom/dsh/android/MainActivity$unrelated$1;"
        m=fx()+[(node(MAIN,"wrong"),
                 [ref(wrong,"<init>",pc=200)])]
        q=a.describe(m)
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_site_count"],1)
    def test_dex_direct_counts_frozen(self):
        bad=[x for x in fx() if x[0]!=node(a.TARGET_LAMBDAS["BOOT"],
                                           "invokeSuspend",
                                           "(Ljava/lang/Object;)Ljava/lang/Object;")]
        self.deny("ORIGINAL_P201_4_1_3_DIRECT_CALL_COUNTS",
                  lambda:a.snapshot(bad))
    def test_lambda_missing_fails(self):
        bad=[x for x in fx() if x[0]!=node(a.TARGET_LAMBDAS["BOOT"],
                                            "invokeSuspend",
                                            "(Ljava/lang/Object;)Ljava/lang/Object;")]
        # With full enforcement, the separate 4/1/3 guard catches it first.
        self.deny("ORIGINAL_P201_4_1_3_DIRECT_CALL_COUNTS",
                  lambda:a.snapshot(bad))
    def test_duplicate_original_method_rejected(self):
        self.deny("DUPLICATE_ORIGINAL_METHOD",
                  lambda:a.snapshot(fx()+[fx()[0]]))
    def test_constructor_count_guard(self):
        with patch.object(a,"MAX_CTORS",0):
            self.deny("ALLOCATION_BOUND",lambda:a.snapshot(fx()))
    def test_graph_edge_guard(self):
        with patch.object(a,"MAX_EDGES",3):
            self.deny("GRAPH_EDGE_BOUND",lambda:a.snapshot(fx()))
    def test_method_limit_guard(self):
        with patch.object(a,"MAX_NODES",1):
            self.deny("ORIGINAL_METHOD_COUNT",lambda:a.snapshot(fx()))
    def test_non_app_source_ignored(self):
        ext="Lthird/party/Spy;"
        q=a.describe(fx()+[(node(ext,"boot"),
                            [ref(a.TARGET_LAMBDAS["BOOT"],"<init>",pc=400)])])
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_site_count"],1)
    def test_no_construction_when_only_allocation(self):
        methods=fx()
        i=next(j for j,(n,_) in enumerate(methods) if n==node(MAIN,"boot"))
        methods[i]=(node(MAIN,"boot"),
                    [(20,"new-instance","v0, "+a.TARGET_LAMBDAS["BOOT"])])
        q=a.describe(methods)
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_site_count"],0)
        self.assertEqual(q["lambda_origins"]["BOOT"]["allocation_site_count"],1)
    def test_no_allocation_when_only_constructor(self):
        methods=fx()
        i=next(j for j,(n,_) in enumerate(methods) if n==node(MAIN,"boot"))
        methods[i]=(node(MAIN,"boot"),
              [ref(a.TARGET_LAMBDAS["BOOT"],"<init>",pc=30,op="invoke-direct")])
        q=a.describe(methods)
        self.assertEqual(q["lambda_origins"]["BOOT"]["constructor_site_count"],1)
        self.assertEqual(q["lambda_origins"]["BOOT"]["allocation_site_count"],0)
    def test_bounded_no_original_operands(self):
        q=json.dumps(a.describe(fx()))
        self.assertNotIn("v0, ",q)
        self.assertNotIn("Bearer ",q)
        self.assertNotIn("cookie=",q)
    def test_exit_is_blocked(self):
        self.assertEqual(a.describe(fx())["release"],"STRUCTURAL_BLOCKED")

if __name__=="__main__":
    unittest.main(verbosity=2)
