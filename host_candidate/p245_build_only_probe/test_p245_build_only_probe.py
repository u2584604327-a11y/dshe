#!/usr/bin/env python3
import unittest
from p245_build_only_probe import patched,restored,helper,OLD,NEW,OWNER,GETTER
class T(unittest.TestCase):
 def s(self):
    return (".class final "+OWNER+"\n.super Ljava/lang/Object;\n"
            ".field final synthetic this$0:Lcom/dsh/android/EngineManager;\n"
            ".method public invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;\n"+
            "    invoke-static {v0}, "+GETTER+"\n"+OLD+"\n.end method\n")
 def test_01_roundtrip(self):self.assertEqual(restored(patched(self.s())),self.s())
 def test_02_single(self):self.assertEqual(patched(self.s()).count(NEW),1)
 def test_03_no_slot(self):
    with self.assertRaises(Exception):patched(self.s().replace(OLD,"nop"))
 def test_04_double(self):
    with self.assertRaises(Exception):patched(self.s()+OLD+"\n")
 def test_05_bad_owner(self):
    with self.assertRaises(Exception):patched(self.s().replace(OWNER,"Lother/X;"))
 def test_06_bad_getter(self):
    with self.assertRaises(Exception):patched(self.s().replace(GETTER,"INVALID"))
 def test_07_two_fields(self):
    with self.assertRaises(Exception):patched(self.s().replace(".method",".field final another:Lcom/dsh/android/EngineManager;\n.method",1))
 def test_08_already_patched(self):
    with self.assertRaises(Exception):patched(patched(self.s()))
 def test_09_not_patched(self):
    with self.assertRaises(Exception):restored(self.s())
 def test_10_no_spawn(self):self.assertNotIn("ProcessBuilder",helper("this$0"))
 def test_11_one_catch(self):self.assertEqual(helper("this$0").count(".catch Ljava/lang/Throwable;"),1)
 def test_12_categories(self):self.assertIn("PROCESS_NULL",helper("this$0"))
 def test_13_categories(self):self.assertIn("PROCESS_NON_NULL",helper("this$0"))
 def test_14_no_ids(self):self.assertNotIn("myUid",helper("this$0"))
 def test_15_extra_helper(self):
    with self.assertRaises(Exception):patched(self.s()+"\n.method public static p245Observe$ci()V\n.end method\n")
if __name__=="__main__":unittest.main()
