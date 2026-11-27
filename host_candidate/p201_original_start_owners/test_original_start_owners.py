#!/usr/bin/env python3
"""P201 graph tests: synthetic method symbols only, never Android/user APK."""
import json
import unittest
from unittest.mock import patch
import audit_original_start_owners as p

ENGINE=p.ENGINE
APP=p.APP
LIFECYCLE="Lcom/dsh/android/MainActivity;"
UI="Lcom/dsh/android/MessageView;"
MODEL="Lcom/dsh/android/ChatViewModel;"
SERVICE="Lcom/dsh/android/EngineService;"
OTHER="Lcom/dsh/android/Other;"
def node(owner,method,desc="()V"):
    return p.key(owner,method,desc)
def ins(pc,caller,desc="()V",opcode="invoke-virtual"):
    return (pc,opcode,"v0, "+ENGINE+"->"+caller+desc)
def fixture():
    # Exactly 4 main, 1 probe, 3 config matching the frozen real P198 result
    # but symbols are fabricated test values and NOT original app evidence.
    sources=[
      (node(LIFECYCLE,"onClick"),[ins(10,"start")]),
      (node(MODEL,"startConversation"),[ins(20,"start")]),
      (node(SERVICE,"resumePrevious"),[ins(30,"start")]),
      (node(OTHER,"invokeSuspend"),[ins(40,"start")]),
      (node(SERVICE,"probe"),[ins(50,"probeBoot")]),
      (node(MODEL,"dumpConfig"),[ins(60,"runDumpConfig")]),
      (node(OTHER,"run"),[ins(70,"runDumpConfig")]),
      (node(LIFECYCLE,"onResume"),[ins(80,"runDumpConfig")]),
      (node(UI,"onMenuItemClick"),[(90,"invoke-interface",
          "v0, "+LIFECYCLE+"->onClick()V")]),
      (node(UI,"onCreate"),[(100,"invoke-virtual",
          "v0, "+MODEL+"->startConversation()V")]),
      (node(OTHER,"unknownEntrypoint"),[(110,"invoke-virtual",
          "v0, "+UI+"->onCreate()V")]),
    ]
    return sources

class P201GraphTests(unittest.TestCase):
    def denied(self,expected,work):
        with self.assertRaises(p.Blocked) as cm:work()
        self.assertEqual(str(cm.exception),"P201_DENY_"+expected)
    def test_eight_exact_calls(self):
        q=p.summarize(fixture())
        self.assertEqual({k:len(v) for k,v in q["entry_modes"].items()},
            {"MAIN":4,"PROBE":1,"CONFIG":3})
    def test_activity_on_click_classification(self):
        self.assertEqual(p.class_role(LIFECYCLE,"onClick"),
                         ("ACTIVITY","USER_EVENT_CALLBACK_SIGNATURE"))
    def test_lifecycle_signature_not_execution(self):
        self.assertEqual(p.class_role(LIFECYCLE,"onResume"),
                         ("ACTIVITY","ANDROID_LIFECYCLE_SIGNATURE"))
        self.assertFalse(p.summarize(fixture())["true_android_ui_event_executed"])
    def test_async_not_trusted_coroutine(self):
        self.assertEqual(p.class_role(OTHER,"invokeSuspend")[1],
                         "ASYNC_OR_FUNCTION_CALLBACK_SIGNATURE")
        self.assertFalse(p.summarize(fixture())[
            "original_engine_coroutine_os_source_attested"])
    def test_direct_call_pc(self):
        result=p.summarize(fixture())
        self.assertEqual(sorted(x["instruction_pc"] for x in result[
             "entry_modes"]["MAIN"]),[10,20,30,40])
    def test_precise_upstream(self):
        nodes,incoming,targets,_=p.build_graph(fixture())
        start=node(LIFECYCLE,"onClick")
        upstream=p.upstream_for(start,incoming)
        self.assertEqual(upstream[0]["sample"][0]["symbol"],
                         "com.dsh.android.MessageView.onMenuItemClick")
    def test_upstream_exact_descriptor(self):
        methods=fixture()
        methods.append((node(UI,"caller"),[(120,"invoke-virtual",
              "v0, "+LIFECYCLE+"->onClick(I)V")]))
        nodes,incoming,targets,_=p.build_graph(methods)
        upstream=p.upstream_for(node(LIFECYCLE,"onClick"),incoming)
        self.assertEqual(upstream[0]["distinct_source_methods"],1)
    def test_no_false_extra_target(self):
        methods=fixture()+[(node(UI,"extra"),
           [ins(200,"startSomething")])]
        self.assertEqual(len(p.build_graph(methods)[2]["MAIN"]),4)
    def test_bad_missing_target_fails_closed(self):
        methods=fixture()[:-1]
        # Missing last upstream does not change exact 8 targets
        self.assertEqual(len(p.build_graph(methods)[2]["MAIN"]),4)
        self.denied("EXPECTED_CONFIG_DIRECT_CALLSITES",
                    lambda:p.build_graph(fixture()[:-4]))
    def test_duplicate_method_is_rejected(self):
        self.denied("DUPLICATE_METHOD_DEFINITION",
            lambda:p.build_graph(fixture()+[fixture()[0]]))
    def test_method_bound(self):
        with patch.object(p,"MAX_NODES",3):
            self.denied("METHOD_BOUND",lambda:p.build_graph(fixture()))
    def test_edges_bound(self):
        with patch.object(p,"MAX_EDGES",3):
            self.denied("GRAPH_EDGE_BOUND",lambda:p.build_graph(fixture()))
    def test_scope_no_outside_app_caller(self):
        ext=("Lcom/otherapp/Outside;","call","()V")
        a=p.summarize(fixture()+[(ext,[(1,"invoke-virtual",
                             "v0, "+ENGINE+"->start()V")])])
        # Ignore calls from non-app method owners even in synthetic streams.
        self.assertEqual(len(a["entry_modes"]["MAIN"]),4)
    def test_other_package_target_not_engine(self):
        out="Lcom/example/EngineManager;"
        methods=fixture()+[(node(UI,"helper"),
         [(1,"invoke-virtual","v0, "+out+"->start()V")])]
        self.assertEqual(len(p.build_graph(methods)[2]["MAIN"]),4)
    def test_reject_high_upstream_depth(self):
        self.denied("UPSTREAM_DEPTH_BOUND",
                    lambda:p.upstream_for(node(UI,"x"),{},4))
    def test_redact_unsafe_symbol(self):
        unsafe=("Lcom/dsh/android/Name-Secret;","API_KEY_TOKEN","()V")
        s=p.safe_symbol(unsafe)
        self.assertTrue(s.startswith("REDACTED_SYMBOL_"))
        self.assertNotIn("Secret",s)
    def test_no_original_operands(self):
        serialized=json.dumps(p.summarize(fixture()))
        self.assertNotIn("v0, ",serialized)
        self.assertNotIn("ProcessBuilder",serialized)
        self.assertNotIn("Bearer ",serialized)
    def test_maximum_upstream_sample(self):
        methods=fixture()
        for i in range(8):
            methods.append((node(APP+"Caller"+str(i)+";","onClick"),
              [(210+i,"invoke-virtual",
                "v0, "+LIFECYCLE+"->onClick()V")]))
        _,incoming,_,_=p.build_graph(methods)
        first=p.upstream_for(node(LIFECYCLE,"onClick"),incoming)[0]
        self.assertEqual(first["distinct_source_methods"],9)
        self.assertEqual(len(first["sample"]),6)
    def test_unknown_event_never_certifies(self):
        x=p.summarize(fixture())
        self.assertFalse(x["p184_original_coroutine_handoff_proven"])
        self.assertFalse(x["original_node_http_ready"])
        self.assertEqual(x["production_release"],"STRUCTURAL_BLOCKED")

if __name__=="__main__":
    unittest.main(verbosity=2)
