#!/usr/bin/env python3
"""P247 independent contract adversarial fixtures; no APK input/output."""
import unittest
from p246_exception_semantics import Deny,decode
from test_p246_exception_semantics import Method,Code,Table,Handler,Try,Pair,Dex,model,make

class P247ContractAudit(unittest.TestCase):
 def must_deny(self,m):
    with self.assertRaises(Deny):decode(m,Dex())
 def test_01_existing_complete_fixture(self):
    self.assertEqual(model(),(6,((0,3,((("Ljava/lang/RuntimeException;",3),),None)),)))
 def test_02_gap_before_final_instruction(self):
    self.must_deny(Method(pcs=[0,2,4,6,10]))
 def test_03_reordered_instruction_offsets(self):
    self.must_deny(Method(pcs=[0,4,2,6,8,10]))
 def test_04_duplicate_instruction_boundary(self):
    self.must_deny(Method(pcs=[0,2,2,6,8,10]))
 def test_05_truncated_decoded_instructions(self):
    self.must_deny(Method(pcs=[0,2,4,6,8]))
 def test_06_decoded_width_exceeds_code_item(self):
    self.must_deny(Method(widths=[2,2,2,2,2,4]))
 def test_07_odd_instruction_width(self):
    self.must_deny(Method(widths=[3,2,2,2,2,2]))
 def test_08_zero_instruction_width(self):
    self.must_deny(Method(widths=[0,2,2,2,2,2]))
 def test_09_unreferenced_different_handler(self):
    self.must_deny(make(table=Table([Handler(),Handler(off=102,pairs=[Pair(4,4)])])))
 def test_10_unreferenced_duplicate_semantic_handler(self):
    self.must_deny(make(table=Table([Handler(),Handler(off=102)])))
 def test_11_same_handler_may_be_shared_by_adjacent_tries(self):
    m=make(tries=[Try(start=0,width=2,off=1),Try(start=2,width=2,off=1)])
    self.assertEqual(len(model(m)[1]),2)
 def test_12_valid_multicodeunit_instructions(self):
    m=Method(code=Code(tries=[Try(start=0,width=2)],
                      table=Table([Handler(pairs=[Pair(3,4)])]),total=6),
             pcs=[0,4,8],widths=[4,4,4])
    self.assertEqual(model(m)[1][0][1],2)
if __name__=="__main__":unittest.main()
