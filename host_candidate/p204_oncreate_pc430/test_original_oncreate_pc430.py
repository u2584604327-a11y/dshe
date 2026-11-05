#!/usr/bin/env python3
"""P204 offline synthetic method instructions only (not original Android)."""
import json
import unittest
from unittest.mock import patch
import audit_original_oncreate_pc430 as p
def original_ref():
    return (p.MAIN,p.CALL_NAME,"()V")

def fixture(conditional=True,fallthrough_returns=True):
    rows=[]
    for pc in range(0,430,2):
        if conditional and pc==4:
            rows.append(p.instruction(pc,"if-eqz",2,(430-pc)//2))
        elif conditional and fallthrough_returns and pc==6:
            rows.append(p.instruction(pc,"return-void",2))
        else:
            rows.append(p.instruction(pc,"nop",2))
    rows.append(p.instruction(430,"invoke-direct",6,None,original_ref()))
    rows.append(p.instruction(436,"return-void",2))
    return rows

class P204Test(unittest.TestCase):
    def blocked(self,label,work):
        with self.assertRaises(p.Blocked) as ex:work()
        self.assertEqual(str(ex.exception),"P204_DENY_"+label)
    def test_exact_anchor_and_descriptor(self):
        q=p.branch_assessment(fixture())
        self.assertEqual(q["callsite_pc"],430)
        self.assertEqual(q["call_target"],"MainActivity.bootEngine")
        self.assertEqual(len(q["call_descriptor_sha256_16"]),16)
    def test_normal_reachable_branch(self):
        q=p.branch_assessment(fixture())
        self.assertEqual(q["normal_path_reachability"],
                         "REACHABLE_IN_CONSERVATIVE_CFG")
    def test_decisive_conditional(self):
        q=p.branch_assessment(fixture())
        self.assertEqual(q["total_potential_condition_branches"],1)
        self.assertEqual(q["possible_conditions_bypassing_callsite"][0]["pc"],4)
    def test_two_arms_same_dest_no_fake_guard(self):
        q=p.branch_assessment(fixture(fallthrough_returns=False))
        self.assertEqual(q["total_potential_condition_branches"],0)
    def test_no_branch_no_guard(self):
        q=p.branch_assessment(fixture(conditional=False))
        self.assertEqual(q["total_potential_condition_branches"],0)
    def test_runtime_not_observed(self):
        q=p.branch_assessment(fixture())
        self.assertEqual(q["original_android_pc430_executed"],"NOT_OBSERVED")
        self.assertEqual(q["original_coroutine_os_owner_generation"],"NOT_ATTESTED")
    def test_node_and_release_denied(self):
        q=p.branch_assessment(fixture())
        self.assertEqual(q["original_p184_receipt_to_coroutine"],"NOT_WIRED")
        self.assertEqual(q["original_arm64_node_http_ready"],"NOT_WIRED")
        self.assertEqual(q["release"],"STRUCTURAL_BLOCKED")
    def test_no_sensitive_raw_operands(self):
        q=json.dumps(p.branch_assessment(fixture()))
        self.assertNotIn("v1, ",q)
        self.assertNotIn("cookie",q)
        self.assertNotIn("Bearer",q)
    def test_wrong_pc_denied(self):
        x=fixture();x[-2]=p.instruction(430,"nop",6)
        self.blocked("PC430_NOT_ORIGINAL_BOOTENGINE_INVOKE",
                     lambda:p.branch_assessment(x))
    def test_wrong_target_denied(self):
        x=fixture()
        x[-2]=p.instruction(430,"invoke-direct",6,None,
                            (p.MAIN,"otherMethod","()V"))
        self.blocked("PC430_NOT_ORIGINAL_BOOTENGINE_INVOKE",
                     lambda:p.branch_assessment(x))
    def test_wrong_owner_denied(self):
        x=fixture()
        x[-2]=p.instruction(430,"invoke-direct",6,None,
                            ("Lother/App;","bootEngine","()V"))
        self.blocked("PC430_NOT_ORIGINAL_BOOTENGINE_INVOKE",
                     lambda:p.branch_assessment(x))
    def test_unknown_descriptor_denied(self):
        x=fixture()
        x[-2]=p.instruction(430,"invoke-direct",6,None,
                            (p.MAIN,"bootEngine","no-descriptor"))
        self.blocked("INVALID_BOOTENGINE_DESCRIPTOR",
                     lambda:p.branch_assessment(x))
    def test_duplicate_boot_call_denied(self):
        x=fixture()
        x[10]=p.instruction(20,"invoke-direct",2,None,original_ref())
        self.blocked("ONCREATE_BOOTENGINE_EDGE_COUNT",
                     lambda:p.branch_assessment(x))
    def test_missing_anchor_denied(self):
        # A valid truncated no-anchor method must not retain an invalid
        # branch to that now-missing PC; that is a separate rejection case.
        x=[i for i in fixture(conditional=False) if i["pc"]<430]
        self.blocked("PC430_NOT_AN_INSTRUCTION",lambda:p.branch_assessment(x))
    def test_invalid_branch_target_denied(self):
        x=fixture()
        x[2]=p.instruction(4,"if-eqz",2,2000)
        self.blocked("BRANCH_NOT_ON_INSTRUCTION",lambda:p.branch_assessment(x))
    def test_negative_branch_out_of_range_denied(self):
        x=fixture()
        x[2]=p.instruction(4,"if-eqz",2,-1000)
        self.blocked("BRANCH_NOT_ON_INSTRUCTION",lambda:p.branch_assessment(x))
    def test_invalid_instruction_gap_denied(self):
        x=fixture()
        x[4]=p.instruction(9,"nop",2)
        self.blocked("INSTRUCTION_GAP_OR_OVERLAP",lambda:p.branch_assessment(x))
    def test_duplicate_pc_denied(self):
        x=fixture()
        x[4]=p.instruction(6,"nop",2)
        self.blocked("DUPLICATE_INSTRUCTION_PC",lambda:p.branch_assessment(x))
    def test_bad_instruction_length_denied(self):
        x=fixture()
        x[3]=p.instruction(6,"return-void",3)
        self.blocked("INVALID_INSTRUCTION_LENGTH",lambda:p.branch_assessment(x))
    def test_conditional_without_fallthrough_denied(self):
        # invoke at final pc430 unchanged; explicit source-level guard
        x=[p.instruction(0,"if-eqz",2,0)]
        self.blocked("CONDITION_MISSING_FALLTHROUGH",lambda:p.graph(x))
    def test_switch_does_not_certify_branch_cases(self):
        x=fixture(conditional=False)
        x[2]=p.instruction(4,"packed-switch",2)
        q=p.branch_assessment(x)
        self.assertTrue(q["switch_or_payload_edges_unexpanded"])
        self.assertEqual(q["original_android_pc430_executed"],"NOT_OBSERVED")
    def test_return_path_no_normal_reachability(self):
        x=fixture(conditional=False)
        x[0]=p.instruction(0,"return-void",2)
        q=p.branch_assessment(x)
        self.assertEqual(q["normal_path_reachability"],
                         "NOT_REACHED_IN_MODELED_CFG")
    def test_loop_stops(self):
        x=fixture(conditional=False)
        x[1]=p.instruction(2,"goto",2,-1)
        q=p.branch_assessment(x)
        self.assertEqual(q["normal_path_reachability"],
                         "NOT_REACHED_IN_MODELED_CFG")
    def test_limit_enforced(self):
        with patch.object(p,"MAX_INSTRUCTIONS",4):
            self.blocked("INSTRUCTION_COUNT",
                         lambda:p.branch_assessment(fixture()))
    def test_depth_data_only(self):
        q=p.branch_assessment(fixture())
        self.assertTrue(q["exception_handler_edges_unexpanded"])
        self.assertTrue(all("pc" in x and "opcode" in x
                            for x in q["immediately_prior_opcodes"]))

if __name__=="__main__":unittest.main(verbosity=2)
