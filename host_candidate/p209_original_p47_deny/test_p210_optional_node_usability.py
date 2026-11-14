#!/usr/bin/env python3
"""P210 optional-only deny candidate: strict synthetic rejection invariants."""
import unittest
from audit_signed_node_bootstrap import Denied
from p210_optional_node_usability import (
    alter_text,alter_inverse_preview,isolate_method,validate_comparison,
    OLD_REF,NEW_REF,BOOT,
)

OLD="    invoke-virtual {v9}, "+OLD_REF+"\n"
NEW="    invoke-static {v9}, "+NEW_REF+"\n"
BASE=(".class public Lcom/dsh/android/termux/TermuxBootstrap;\n"
      ".method private final nodeIsUsable(Ljava/io/File;)Z\n"
      "    .registers 12\n"
      "    :try_start\n"+OLD+
      "    move-result-object v0\n"
      "    :try_end\n"
      "    .catchall {:try_start .. :try_end} :catch_all\n"
      "    return v0\n"
      ".end method\n"
      ".method private other()V\n    return-void\n.end method\n")

class I:
    def __init__(self,op,out="",size=2):self.op,self.out,self.size=op,out,size
    def get_name(self):return self.op
    def get_output(self):return self.out
    def get_length(self):return self.size
class Code:
    def __init__(self,register=12,tries=(),handlers=()):
        self.register,self.tries,self.handlers=register,tries,handlers
    def get_registers_size(self):return self.register
    def get_ins_size(self):return 1
    def get_outs_size(self):return 1
    def get_tries(self):return list(self.tries)
    def get_handlers(self):return None
class Method:
    def __init__(self,rows,register=12,code=True):
        self.rows=rows
        self.code=Code(register) if code else None
    def get_code(self):return self.code
    def get_instructions_idx(self):return self.rows
OWNER=BOOT
TARGET=(OWNER,"nodeIsUsable","(Ljava/io/File;)Z")
OTHER=(OWNER,"getNodeBinary","()Ljava/io/File;")

def keymap(override=None,other_changed=False,register=12):
    old=[(232,I("invoke-virtual","v9, "+OLD_REF,6)),
         (238,I("move-result-object","v0",2)),
         (240,I("return","v0",2))]
    new=[(232,I("invoke-static","v9, "+NEW_REF,6)),
         (238,I("move-result-object","v0",2)),
         (240,I("return","v0",2))]
    non_target=[(0,I("return-object","v0",2))]
    if other_changed:non_target=[(0,I("nop","",2))]
    return {TARGET:Method(override or new,register=register),
            OTHER:Method(non_target)}, {
            TARGET:Method(old), OTHER:Method([(0,I("return-object","v0",2))])
           }

class CandidateNegatives(unittest.TestCase):
    def test_reversible_only_one_smali_call(self):
        amended=alter_text(BASE)
        self.assertEqual(amended,BASE.replace(OLD,NEW))
        self.assertEqual(alter_text(amended,True),BASE)
    def test_no_unrelated_method_edit(self):
        self.assertIn(".method private other()V\n    return-void",alter_text(BASE))
    def test_two_start_sites_refused(self):
        with self.assertRaises(Denied):alter_text(BASE.replace(OLD,OLD+OLD))
    def test_no_start_site_refused(self):
        with self.assertRaises(Denied):alter_text(BASE.replace(OLD,""))
    def test_only_matching_method_can_be_altered(self):
        with self.assertRaises(Denied):
            alter_text(BASE.replace(OLD,"").replace("return-void",OLD+"    return-void"))
    def test_prepatched_input_refused(self):
        with self.assertRaises(Denied):alter_text(BASE.replace(OLD,NEW))
    def test_double_restore_refused(self):
        with self.assertRaises(Denied):alter_text(BASE,True)
    def test_valid_full_method_parity(self):
        candidate,baseline=keymap()
        self.assertEqual(validate_comparison(baseline,candidate),2)
    def test_single_opcode_width_drift_denied(self):
        candidate,baseline=keymap(override=[
            (232,I("invoke-static","v9, "+NEW_REF,8)),
            (240,I("move-result-object","v0",2)),
            (242,I("return","v0",2))])
        with self.assertRaises(Denied):
            validate_comparison(baseline,candidate)
    def test_unrelated_method_changed_refused(self):
        candidate,baseline=keymap(other_changed=True)
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)
    def test_register_drift_refused(self):
        candidate,baseline=keymap(register=13)
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)
    def test_wrong_target_refused(self):
        candidate,baseline=keymap(override=[
            (232,I("invoke-static","v9, Lcom/example/Other;->launch(Ljava/lang/ProcessBuilder;)Ljava/lang/Process;",6)),
            (238,I("move-result-object","v0",2)),
            (240,I("return","v0",2))])
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)
    def test_changed_register_operand_refused(self):
        candidate,baseline=keymap(override=[
            (232,I("invoke-static","v8, "+NEW_REF,6)),
            (238,I("move-result-object","v0",2)),
            (240,I("return","v0",2))])
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)
    def test_missing_method_refused(self):
        candidate,baseline=keymap()
        del candidate[OTHER]
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)
    def test_no_extra_original_callsite(self):
        candidate,baseline=keymap(override=[
            (232,I("invoke-static","v9, "+NEW_REF,6)),
            (238,I("invoke-virtual","v9, "+OLD_REF,6)),
            (244,I("return","v0",2))])
        with self.assertRaises(Denied):validate_comparison(baseline,candidate)

if __name__=="__main__":unittest.main(verbosity=2)
