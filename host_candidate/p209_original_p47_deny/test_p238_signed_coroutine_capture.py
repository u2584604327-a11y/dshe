#!/usr/bin/env python3
"""P238 receiver capture classifier: synthetic positive and strict negatives."""
import unittest
from p238_signed_coroutine_capture import capture_verdict, START, ENGINE

class CaptureTests(unittest.TestCase):
    def verdict(self, descriptors, pc182_output, receiver_register=8):
        return capture_verdict(descriptors, pc182_output, receiver_register)

    def setUp(self):
        self.one = [ENGINE,"Ljava/lang/String;"]
        self.output = "v1, v8, "+START+"->this$0 "+ENGINE

    def test_valid_receiver_and_single_engine_field(self):
        self.assertEqual(self.verdict(self.one,self.output),("ONE","CANDIDATE"))

    def test_no_engine_capture(self):
        self.assertEqual(self.verdict(["Ljava/lang/String;"],self.output),
                         ("NONE","NOT_ATTESTED"))

    def test_multiple_engine_fields_not_safe(self):
        self.assertEqual(self.verdict([ENGINE,ENGINE],self.output),
                         ("MULTIPLE","NOT_ATTESTED"))

    def test_wrong_receiver_register(self):
        self.assertEqual(self.verdict(self.one,self.output.replace("v8","v9")),
                         ("ONE","NOT_ATTESTED"))

    def test_wrong_owner(self):
        self.assertEqual(self.verdict(self.one,self.output.replace(START,
                        "Lcom/unknown/Fake;")),("ONE","NOT_ATTESTED"))

    def test_wrong_type(self):
        self.assertEqual(self.verdict(self.one,self.output.replace(
                        ENGINE,"Ljava/lang/Object;")),("ONE","NOT_ATTESTED"))

    def test_wrong_output_opcode_shape(self):
        self.assertEqual(self.verdict(self.one,"v1, v2, "+START+"->this$0 "+ENGINE),
                         ("ONE","NOT_ATTESTED"))

    def test_smali_p0_text_not_accepted_as_dex_register(self):
        self.assertEqual(self.verdict(self.one,self.output.replace("v8","p0")),
                         ("ONE","NOT_ATTESTED"))

    def test_wrong_computed_receiver_register(self):
        self.assertEqual(self.verdict(self.one,self.output,7),
                         ("ONE","NOT_ATTESTED"))

    def test_empty_data_cannot_prove_capture(self):
        self.assertEqual(self.verdict([],""),("NONE","NOT_ATTESTED"))

if __name__=="__main__":
    unittest.main(verbosity=2)
