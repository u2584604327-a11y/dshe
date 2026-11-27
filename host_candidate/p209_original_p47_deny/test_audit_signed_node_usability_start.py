#!/usr/bin/env python3
"""P209 fail-closed synthetic tests: original Node probe start outside P181."""
import tempfile
import unittest
from pathlib import Path

from audit_signed_node_bootstrap import Denied
from audit_signed_node_usability_start import (
    direct_start_rows,check_spawn_coverage,verify_p181_scope,
)

class Ins:
    def __init__(self,op="nop",out="",size=2):
        self.op,self.out,self.size=op,out,size
    def get_name(self):return self.op
    def get_output(self):return self.out
    def get_length(self):return self.size

START="v0, Ljava/lang/ProcessBuilder;->start()Ljava/lang/Process;"
OTHER="v0, Lcom/example/Thing;->check(Ljava/lang/ProcessBuilder;)Z"

def good():
    return [(0,Ins("invoke-virtual",START,6)),
            (6,Ins("move-result-object","v0",2)),
            (8,Ins("return-object","v0",2))]

class UnmediatedStartTests(unittest.TestCase):
    def test_original_one_direct_start(self):
        self.assertEqual(direct_start_rows(good()),[(0,"invoke-virtual",6)])
    def test_signature_only_does_not_count_start(self):
        rows=[(0,Ins("invoke-virtual",OTHER))]
        self.assertEqual(direct_start_rows(rows),[])
    def test_noninvoke_text_does_not_count_start(self):
        self.assertEqual(direct_start_rows(
            [(0,Ins("const-string",START))]),[])
    def test_direct_start_parity(self):
        pc,covered=check_spawn_coverage(good(),good(),[])
        self.assertEqual((pc,covered),(0,[]))
    def test_swapped_or_removed_derived_start_denied(self):
        derived=[(0,Ins("invoke-static",START,6)),*good()[1:]]
        with self.assertRaises(Denied):
            check_spawn_coverage(good(),derived,[])
        with self.assertRaises(Denied):
            check_spawn_coverage(good(),good()[1:],[])
    def test_two_signed_sites_refused(self):
        rows=[*good(),(12,Ins("invoke-virtual",START,6))]
        with self.assertRaises(Denied):
            check_spawn_coverage(rows,rows,[])
    def test_signed_wrong_opcode_refused(self):
        rows=[(0,Ins("invoke-static",START,6)),*good()[1:]]
        with self.assertRaises(Denied):
            check_spawn_coverage(rows,rows,[])
    def test_static_handler_cover_and_catch_all(self):
        pc,covers=check_spawn_coverage(
            good(),good(),[(0,6,1,True),(6,10,1,False)])
        self.assertEqual(pc,0)
        self.assertEqual(covers,[(0,6,1,True)])
    def test_source_scope_exact_known_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"p47_gate.py"
            p.write_text('P181_THREE_ORIGINAL_START_DENY\n'
                         'EngineManager.smali\n'
                         '"probeBoot":\n"runDumpConfig":\n',encoding="utf-8")
            self.assertTrue(verify_p181_scope(p))
    def test_source_claiming_node_is_covered_is_not_assumed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"p47_gate.py"
            p.write_text('P181_THREE_ORIGINAL_START_DENY\n'
                         'EngineManager.smali\n'
                         '"probeBoot":\n"runDumpConfig":\n'
                         'nodeIsUsable\n',encoding="utf-8")
            with self.assertRaises(Denied):verify_p181_scope(p)

if __name__=="__main__":unittest.main(verbosity=2)
