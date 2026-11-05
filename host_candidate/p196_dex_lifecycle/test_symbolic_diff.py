#!/usr/bin/env python3
"""P196 pure-python deliberately synthetic negative cases; zero APK access."""
import dataclasses
import unittest
from audit_exact_v138_dex import (
    Denied, LIFECYCLE_EDGES, MethodSnapshot, Op, compare_method,
    check_original_lifecycle, ORIGINAL_START, expected_target,
)

def mk(site="MAIN",kind="correct"):
    label,bridge,pc=("MAIN","start",3912) if site=="MAIN" else (
        ("PROBE","probeOrDeny",100) if site=="PROBE" else
        ("CONFIG","configOrDeny",200))
    # 35c invoke format has width exactly six bytes. Synthetic PCs are
    # intentionally noncontinuous: equality, not a fake APK, is under test.
    original=Op(pc,"invoke-virtual",6,"v2, "+ORIGINAL_START)
    replacement=Op(pc,"invoke-static",6,"v2, "+expected_target(bridge))
    ops=(Op(20,"const/4",2,"v0, 1"),original,
         Op(pc+6,"return-void",2,""))
    after=(ops[0],replacement,ops[2])
    meta=(8,2,3,0,100)
    first=MethodSnapshot("method","()V",1,meta,(),ops)
    second=MethodSnapshot("method","()V",1,meta,(),after)
    return label,bridge,pc,first,second

class TestP196SymbolicDex(unittest.TestCase):
    def assertDenied(self, code, f):
        with self.assertRaises(Denied) as c:f()
        self.assertEqual("P196_DENY_"+code,str(c.exception))
    def checkPair(self,site="MAIN"):
        label,bridge,pc,a,b=mk(site)
        self.assertEqual((pc,3),compare_method(a,b,label,bridge,pc))
        return label,bridge,pc,a,b
    def change(self,s,**kw):
        return dataclasses.replace(s,**kw)
    def changeOp(self,s,index,**kw):
        ops=list(s.ops);ops[index]=dataclasses.replace(ops[index],**kw)
        return self.change(s,ops=tuple(ops))
    def test_main_probe_config_exact(self):
        for mode in ("MAIN","PROBE","CONFIG"):self.checkPair(mode)
    def test_no_rewrite_fails(self):
        label,bridge,pc,a,b=mk()
        self.assertDenied("MAIN_EXACTLY_ONE_REWRITE_REQUIRED",
            lambda:compare_method(a,a,label,bridge,pc))
    def test_wrong_bridge_fails(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,1,operand="v2, "+expected_target("probeOrDeny"))
        self.assertDenied("MAIN_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_3912",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_wrong_caller_register(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,1,operand="v3, "+expected_target(bridge))
        self.assertDenied("MAIN_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_3912",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_added_instruction_rejected(self):
        label,bridge,pc,a,b=mk()
        b=self.change(b,ops=b.ops+(Op(3919,"return-void",2,""),))
        self.assertDenied("MAIN_INSTRUCTION_COUNT_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_changed_lifecycle_instruction_rejected(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,0,operand="v0, 0")
        self.assertDenied("MAIN_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_20",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_changed_instruction_width(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,1,width=8)
        self.assertDenied("MAIN_PC_OR_WIDTH_DRIFT_3912",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_changed_pc_rejected(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,2,pc=5000)
        self.assertDenied("MAIN_PC_OR_WIDTH_DRIFT_3918",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_wrong_opcode(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,1,name="invoke-interface")
        self.assertDenied("MAIN_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_3912",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_new_unapproved_literal(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,0,name="const/16",operand="v0, 0")
        self.assertDenied("MAIN_UNAUTHORIZED_OPCODE_OR_OPERAND_PC_20",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_layout_registers_changed(self):
        label,bridge,pc,a,b=mk()
        b=self.change(b,layout=(9,2,3,0,100))
        self.assertDenied("MAIN_REGISTER_OR_TRY_LAYOUT_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_access_flags_changed(self):
        label,bridge,pc,a,b=mk()
        b=self.change(b,access_flags=9)
        self.assertDenied("MAIN_METHOD_FLAGS_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_method_descriptor_changed(self):
        label,bridge,pc,a,b=mk()
        b=self.change(b,descriptor="(I)V")
        self.assertDenied("MAIN_METHOD_SIGNATURE_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_handler_topology_changed(self):
        label,bridge,pc,a,b=mk()
        b=self.change(b,handlers=((100,2,(("Ljava/lang/Exception;",120),)),))
        self.assertDenied("MAIN_CATCH_TOPOLOGY_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_original_main_start_pc_cannot_move(self):
        label,bridge,pc,a,b=mk()
        a=self.changeOp(a,1,pc=3900)
        b=self.changeOp(b,1,pc=3900)
        self.assertDenied("MAIN_FIXED_ORIGINAL_PC_DRIFT",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_second_rewrite_is_never_allowed(self):
        label,bridge,pc,a,b=mk()
        x=Op(4010,"invoke-virtual",6,"v4, "+ORIGINAL_START)
        y=Op(4010,"invoke-static",6,"v4, "+expected_target(bridge))
        a=self.change(a,ops=a.ops+(x,))
        b=self.change(b,ops=b.ops+(y,))
        self.assertDenied("MAIN_EXACTLY_ONE_REWRITE_REQUIRED",
            lambda:compare_method(a,b,label,bridge,pc))
    def test_lifecycle_every_pinned_edge_required(self):
        ops=[Op(pc,"invoke-virtual",6,"v0, "+expected)
             for pc,expected in LIFECYCLE_EDGES.items()]
        main=MethodSnapshot("invokeSuspend","(Ljava/lang/Object;)Ljava/lang/Object;",
                            1,(12,2,3,0,5000),(),tuple(ops))
        check_original_lifecycle(main)
        bad=[o for o in ops if o.pc!=4026]
        self.assertDenied("ORIGINAL_LIFECYCLE_EDGE_DRIFT_PC_4026",
            lambda:check_original_lifecycle(self.change(main,ops=tuple(bad))))
    def test_exception_no_raw_operand_exposure(self):
        label,bridge,pc,a,b=mk()
        b=self.changeOp(b,0,operand="PRIVATE_COOKIE_SECRET")
        with self.assertRaises(Denied) as c:
            compare_method(a,b,label,bridge,pc)
        self.assertNotIn("PRIVATE_COOKIE_SECRET",str(c.exception))

if __name__=="__main__":
    unittest.main(verbosity=2)
