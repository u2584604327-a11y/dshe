#!/usr/bin/env python3
"""P198 synthetic caller extraction negatives; no actual APK or network."""
import dataclasses
import json
import unittest
from audit_entry_callers import (Block,APP_PREFIX,ENGINE_COROUTINE,
  TARGET_OWNER,scan_stream,summarize,callable_category,source_entry_kind)

def method(owner, name, *pairs):
    return (owner,name,[(pc,op,out) for pc,op,out in pairs])

COROUTINE=method(ENGINE_COROUTINE,"invokeSuspend",
   (3912,"invoke-virtual","v1, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"))
def target(name):
    return "v5, "+TARGET_OWNER+"->"+name+"()V"

def stream(*others):
    return [COROUTINE,*others]

class P198GraphTest(unittest.TestCase):
    def denied(self,reason,callback):
        with self.assertRaises(Block) as cm:callback()
        self.assertEqual("P198_DENY_"+reason,str(cm.exception))
    def test_normal_direct_modes(self):
        app="Lcom/dsh/android/MainActivity;"
        svc="Lcom/dsh/android/SyncService;"
        m=[method(app,"onStart",(12,"invoke-virtual",target("start"))),
           method(svc,"boot",(24,"invoke-virtual",target("probeBoot"))),
           method(TARGET_OWNER,"config",(36,"invoke-direct",target("runDumpConfig")))]
        found=scan_stream(stream(*m))
        self.assertEqual(tuple(len(found[k]) for k in ("MAIN","PROBE","CONFIG")),(1,1,1))
        self.assertEqual(found["MAIN"][0]["owner_category"],"ACTIVITY_CALLER")
        self.assertEqual(found["PROBE"][0]["owner_category"],"SERVICE_CALLER")
        self.assertEqual(found["CONFIG"][0]["owner_category"],"ENGINE_MANAGER_INTERNAL")
    def test_direct_callsite_pc(self):
        result=scan_stream(stream(method(TARGET_OWNER,"client",
          (200,"invoke-virtual",target("start")))))
        self.assertEqual(result["MAIN"][0]["pc"],200)
    def test_callsite_not_confused_with_callee_spawn(self):
        found=scan_stream(stream())
        self.assertEqual(len(found["MAIN"]),0)
    def test_indirect_not_proven(self):
        out=summarize(scan_stream(stream()))
        self.assertEqual(out["targets"]["MAIN"]["observation"],
          "NO_DIRECT_CALLSITE_OBSERVED_INDIRECT_DISPATCH_UNKNOWN")
        self.assertFalse(out["real_android_coroutine_invoked"])
        self.assertFalse(out["original_coroutine_os_generation_attested"])
        self.assertEqual(out["release"],"STRUCTURAL_BLOCKED")
    def test_untrusted_method_names_no_raw_output(self):
        name="SECRET_COOKIE=PRIVATE_TOKEN"
        found=scan_stream(stream(method(APP_PREFIX+"Client;",name,
           (64,"invoke-virtual",target("start")))))
        serialized=json.dumps(summarize(found))
        self.assertNotIn("SECRET_COOKIE",serialized)
        self.assertNotIn("PRIVATE_TOKEN",serialized)
        self.assertEqual(len(found["MAIN"][0]["caller_id_hash"]),16)
    def test_confused_owner_denied(self):
        o="Lcom/malicious/EngineManager;"
        found=scan_stream(stream(method(o,"run",
             (4,"invoke-static","v1, "+o+"->start()V"))))
        self.assertEqual(sum(map(len,found.values())),0)
    def test_wrong_target_symbol_not_counted(self):
        found=scan_stream(stream(method(TARGET_OWNER,"call",
          (5,"invoke-virtual",target("startOver")))))
        self.assertEqual(len(found["MAIN"]),0)
    def test_noninvoke_not_counted(self):
        found=scan_stream(stream(method(TARGET_OWNER,"call",
          (7,"const-string",target("start")))))
        self.assertEqual(len(found["MAIN"]),0)
    def test_exactly_one_coroutine_required(self):
        self.denied("EXACTLY_ONE_ENGINE_COROUTINE",lambda:scan_stream([]))
        self.denied("EXACTLY_ONE_ENGINE_COROUTINE",
                    lambda:scan_stream([COROUTINE,COROUTINE]))
    def test_external_category(self):
        self.assertEqual(callable_category("Ljava/lang/String;"),"EXTERNAL_OR_UNKNOWN")
    def test_other_app_category(self):
        self.assertEqual(callable_category("Lcom/dsh/android/Bridge;"),"ORIGINAL_APP_OTHER")
    def test_coroutine_category(self):
        self.assertEqual(callable_category(ENGINE_COROUTINE),"ENGINE_COROUTINE")
    def test_invalid_bounded_method_count(self):
        # Cannot produce 150001 objects cheaply here; verify a cheap
        # direct bound by 2001 matching calls within 1 method.
        big=[(i,"invoke-virtual",target("start")) for i in range(2001)]
        self.denied("DIRECT_CALLSITE_BOUND",
                    lambda:scan_stream(stream(method(TARGET_OWNER,"repeat",*big))))
    def test_failed_binder_production_assertions(self):
        out=summarize(scan_stream(stream()))
        self.assertFalse(out["binder_receipt_delivered_to_original_coroutine"])
        self.assertFalse(out["production_node_http_ready"])
        self.assertEqual(out["host_unauthorized_process_spawn"],"DENY")

    def test_start_lifecycle_owner_is_static_name_only(self):
        found=scan_stream(stream(method(APP_PREFIX+"MainActivity;","onCreate",
            (16,"invoke-virtual",target("start")))))
        row=summarize(found)["targets"]["MAIN"]
        self.assertEqual(row["source_entry_kinds"],{"LIFECYCLE_NAMED_METHOD":1})
        self.assertEqual(row["owner_entry_matrix"],
            {"ACTIVITY_CALLER__LIFECYCLE_NAMED_METHOD":1})
    def test_user_click_name_is_not_a_verified_real_click(self):
        found=scan_stream(stream(method(APP_PREFIX+"MainActivity;","onClick",
            (16,"invoke-virtual",target("start")))))
        report=summarize(found)
        self.assertEqual(report["targets"]["MAIN"]["source_entry_kinds"],
                         {"UI_CALLBACK_NAMED_METHOD":1})
        self.assertFalse(report["genuine_user_action_trigger_attested"])
    def test_suspend_method_cannot_be_mislabeled_click(self):
        found=scan_stream(stream(method(APP_PREFIX+"MainActivity$job$1;","invokeSuspend",
            (16,"invoke-virtual",target("start")))))
        self.assertEqual(found["MAIN"][0]["source_entry_kind"],
                         "COROUTINE_CONTINUATION")
    def test_kotlin_invoke_is_ambiguous_not_ui_proof(self):
        self.assertEqual(source_entry_kind(APP_PREFIX+"MainActivity$callback$1;","invoke"),
                         "KOTLIN_INVOKE_AMBIGUOUS")
    def test_class_initialization_not_ui_proof(self):
        self.assertEqual(source_entry_kind(APP_PREFIX+"Anything;","<init>"),
                         "CLASS_INITIALIZATION")
        self.assertEqual(source_entry_kind(APP_PREFIX+"Anything;","<clinit>"),
                         "CLASS_INITIALIZATION")
    def test_malicious_source_text_never_appears_in_categories(self):
        found=scan_stream(stream(method(APP_PREFIX+"MainActivity;","SECRET_API_KEY",
            (13,"invoke-virtual",target("start")))))
        report=json.dumps(summarize(found),sort_keys=True)
        self.assertNotIn("SECRET_API_KEY",report)
        self.assertIn("OTHER_METHOD_NO_UI_PROOF",report)

if __name__=="__main__":
    unittest.main(verbosity=2)
