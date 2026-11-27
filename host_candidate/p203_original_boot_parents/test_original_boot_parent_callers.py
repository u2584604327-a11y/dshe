#!/usr/bin/env python3
"""P203 synthetic negative/edge tests; NOT original Android/real user evidence."""
import json
import unittest
from unittest.mock import patch
import audit_original_boot_parent_callers as a

p=a.p201
MAIN=a.MAIN
ENGINE=p.ENGINE
def node(owner,name,desc="()V"):return p.key(owner,name,desc)
def inv(owner,name,pc=12,opcode="invoke-direct",desc="()V"):
    return pc,opcode,"v0, "+owner+"->"+name+desc

def fixture():
    out=[]
    for i,(tag,(owner,parent,pc,lclass)) in enumerate(a.PARENTS.items()):
        out.append((node(owner,parent),[inv(lclass,"<init>",pc=pc)]))
        out.append((node(lclass,"invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;"),
                    [inv(ENGINE,"start",pc=100+i)]))
    out.extend([
      (node(ENGINE,"probeBoot$default"),[inv(ENGINE,"probeBoot",pc=208)]),
      (node(ENGINE,"preflight"),[inv(ENGINE,"runDumpConfig",pc=209),
                                 inv(ENGINE,"runDumpConfig",pc=210)]),
      (node(ENGINE,"rebuildEngine"),[inv(ENGINE,"runDumpConfig",pc=211)]),
      (node("Lcom/dsh/android/MainActivity$someCallback$1;","invokeSuspend"),
        [inv(MAIN,"bootEngine",pc=120)]),
      (node(MAIN,"access$bootEngine"),[inv(MAIN,"bootEngine",pc=130)]),
      (node(MAIN,"onClick"),[inv(MAIN,"access$bootEngine",pc=140)]),
      (node(MAIN,"onCreate"),[inv(MAIN,"autoEnterSafeMode",pc=150)]),
      (node("Lcom/dsh/android/SomeController;","onChanged"),
        [inv(a.OBS_PARENT,"emit",pc=160)]),
      (node(MAIN,"enterMenu"),[inv(MAIN,"enterSafeMode",pc=170)]),
    ])
    return out

class P203Test(unittest.TestCase):
    def denied(self,tag,fn):
        with self.assertRaises(a.Blocked) as z:fn()
        self.assertEqual(str(z.exception),"P203_DENY_"+tag)
    def test_four_verified_anchor_parents(self):
        q=a.analyze(fixture())
        self.assertEqual(set(q["parent_callchains"]),set(a.PARENTS))
        self.assertTrue(all(v["p202_anchor_original_verified"] for v
                            in q["parent_callchains"].values()))
    def test_exact_original_anchor_pc(self):
        q=a.analyze(fixture())
        self.assertEqual({k:v["p202_constructor_pc"] for k,v in
                          q["parent_callchains"].items()},
                         {"BOOT":26,"AUTO_SAFE":104,"MANUAL_SAFE":104,"OBSERVE":1432})
    def test_direct_callers_of_boot(self):
        q=a.analyze(fixture())["parent_callchains"]["BOOT"]
        self.assertEqual(q["direct_caller_count"],2)
        self.assertIn("com.dsh.android.MainActivity.access$bootEngine",
            [x["source_symbol"] for x in q["sampled_source_methods"]])
    def test_real_event_not_proven(self):
        q=a.analyze(fixture())
        self.assertFalse(q["actual_original_android_ui_interaction"])
        self.assertFalse(q["genuine_engine_manager_coroutine_invoked"])
    def test_p184_authority_not_proven(self):
        q=a.analyze(fixture())
        self.assertFalse(q["os_owner_epoch_attested"])
        self.assertFalse(q["p184_receipt_to_original_coroutine"])
        self.assertFalse(q["original_arm64_node_http_ready"])
    def test_kotlin_accessor_hint(self):
        self.assertEqual(a.role_of(node(MAIN,"access$bootEngine"))[1],
            "KOTLIN_SYNTHETIC_ACCESSOR_SIGNATURE")
    def test_lifecycle_hint_non_authoritative(self):
        self.assertEqual(a.role_of(node(MAIN,"onCreate"))[1],
                         "POSSIBLE_LIFECYCLE_SIGNATURE")
    def test_click_hint_non_authoritative(self):
        self.assertEqual(a.role_of(node(MAIN,"onClick"))[1],
                         "POSSIBLE_USER_CALLBACK_SIGNATURE")
    def test_unknown_method_hint(self):
        self.assertEqual(a.role_of(node(MAIN,"bootEngine"))[1],
                         "UNCLASSIFIED_METHOD_SIGNATURE")
    def test_absent_direct_caller_does_not_invent(self):
        z=[(n,ins) for n,ins in fixture() if n!=node(MAIN,"enterMenu")]
        q=a.analyze(z)["parent_callchains"]["MANUAL_SAFE"]
        self.assertEqual(q["direct_caller_count"],0)
        self.assertEqual(q["method_trigger_classified_by_execution"],"NOT_PROVEN")
    def test_wrong_pc_denied(self):
        b=fixture()
        n0,ins=b[0]
        b[0]=(n0,[inv(a.PARENTS["BOOT"][3],"<init>",pc=27)])
        self.denied("EXACT_BOOT_P202_CONSTRUCTOR_PC",lambda:a.analyze(b))
    def test_wrong_lambda_owner_denied(self):
        b=fixture()
        n0,ins=b[0]
        b[0]=(n0,[inv(a.PARENTS["AUTO_SAFE"][3],"<init>",pc=26)])
        self.denied("EXACT_BOOT_P202_CONSTRUCTOR_PC",lambda:a.analyze(b))
    def test_non_constructor_denied(self):
        b=fixture()
        n0,_=b[0]
        b[0]=(n0,[inv(a.PARENTS["BOOT"][3],"create",pc=26)])
        self.denied("EXACT_BOOT_P202_CONSTRUCTOR_PC",lambda:a.analyze(b))
    def test_no_invoke_suspend_denied(self):
        b=[(n,ins) for n,ins in fixture() if n[0]!=a.PARENTS["BOOT"][3]]
        # Keep the frozen P201 four calls intact while deleting the BOOT
        # suspend method; otherwise its independent 4/1/3 guard fires first.
        b.append((node(MAIN,"syntheticReplacementMainCall"),
                  [inv(ENGINE,"start",pc=400)]))
        self.denied("ORIGINAL_BOOT_SUSPEND_CLASS",lambda:a.analyze(b))
    def test_frozen_main_count_denied(self):
        b=fixture()
        idx=next(i for i,(n,_) in enumerate(b) if
                 n[0]==a.PARENTS["BOOT"][3] and n[1]=="invokeSuspend")
        n0,_=b[idx]
        b[idx]=(n0,[inv(ENGINE,"startOther",pc=101)])
        self.denied("P201_4_1_3_DIRECT_INVOCATIONS",lambda:a.analyze(b))
    def test_duplicate_method_denied(self):
        self.denied("DUPLICATE_METHOD",lambda:a.analyze(fixture()+[fixture()[0]]))
    def test_method_limit_denied(self):
        with patch.object(a,"MAX_METHODS",1):
            self.denied("METHOD_COUNT",lambda:a.analyze(fixture()))
    def test_invoke_edge_limit_denied(self):
        with patch.object(a,"MAX_EDGES",2):
            self.denied("INVOKE_GRAPH_EDGE_LIMIT",lambda:a.analyze(fixture()))
    def test_upstream_depth_limit_denied(self):
        self.denied("DEPTH_LIMIT",lambda:a.inbound_paths(
            node(MAIN,"bootEngine"),{},5))
    def test_recursion_does_not_loop(self):
        cyc=[(node(MAIN,"cycleA"),[inv(MAIN,"cycleB")]),
             (node(MAIN,"cycleB"),[inv(MAIN,"cycleA")])]
        b=fixture()+cyc
        q=a.analyze(b)
        self.assertLess(q["parent_callchains"]["BOOT"]["distinct_upstream_methods"],20)
    def test_other_package_source_ignored(self):
        ext=("Lcom/external/NotApp;","onClick","()V")
        b=fixture()+[(ext,[inv(MAIN,"bootEngine")])]
        self.assertEqual(a.analyze(b)["parent_callchains"]["BOOT"]["direct_caller_count"],2)
    def test_redacted_no_invoke_operands(self):
        s=json.dumps(a.analyze(fixture()))
        self.assertNotIn("v0, ",s)
        self.assertNotIn("Bearer",s)
        self.assertEqual(a.analyze(fixture())["release"],"STRUCTURAL_BLOCKED")

if __name__=="__main__":unittest.main(verbosity=2)
