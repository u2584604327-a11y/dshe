#!/usr/bin/env python3
"""P209 locked Node installer: exact original target identity / bounded negatives."""
import unittest
from audit_signed_node_bootstrap import Denied
from audit_signed_node_locked import resolve_method,exact_original_call,static_method_stats

OWNER="Lcom/dsh/android/termux/TermuxBootstrap;"
DESC="()V"

class I:
    def __init__(self,op="nop",out=""):self.op,self.out=op,out
    def get_name(self):return self.op
    def get_output(self):return self.out

class Method:
    def __init__(self,name="installNodeRuntimeLocked",desc=DESC,code=True,rows=None):
        self.name,self.desc,self.code,self.rows=name,desc,code,rows or []
    def get_name(self):return self.name
    def get_descriptor(self):return self.desc
    def get_code(self):return self if self.code else None
    def get_tries(self):return []
    def get_instructions_idx(self):return self.rows

class Cls:
    def __init__(self,name=OWNER,methods=None):
        self.name,self.methods=name,[Method()] if methods is None else methods
    def get_name(self):return self.name
    def get_methods(self):return self.methods

class Dex:
    def __init__(self,classes=None):self.classes=[Cls()] if classes is None else classes
    def get_classes(self):return self.classes

class TraceTests(unittest.TestCase):
    def test_unique_method_resolves_original_exact(self):
        self.assertEqual(resolve_method([("classes.dex",Dex())],OWNER,
                        "installNodeRuntimeLocked")[0],"classes.dex")
    def test_duplicate_method_refused(self):
        dex=Dex([Cls(methods=[Method(),Method()])])
        with self.assertRaises(Denied):
            resolve_method([("classes.dex",dex)],OWNER,"installNodeRuntimeLocked")
    def test_missing_method_refused(self):
        with self.assertRaises(Denied):
            resolve_method([("classes.dex",Dex([Cls(methods=[])])],
                           OWNER,"installNodeRuntimeLocked")
    def test_method_without_code_refused(self):
        with self.assertRaises(Denied):
            resolve_method([("classes.dex",Dex([Cls(methods=[Method(code=False)])])],
                           OWNER,"installNodeRuntimeLocked")
    def test_unique_original_invoke_target(self):
        rows=[(130,I("invoke-static",
                     "v0, "+OWNER+"->access$installNodeRuntimeLocked()V"))]
        pc,ins=exact_original_call(rows,OWNER,"access$installNodeRuntimeLocked",DESC)
        self.assertEqual(pc,130)
    def test_noninvoke_text_does_not_link(self):
        rows=[(130,I("const-string",OWNER+"->access$installNodeRuntimeLocked()V"))]
        with self.assertRaises(Denied):
            exact_original_call(rows,OWNER,"access$installNodeRuntimeLocked",DESC)
    def test_incorrect_descriptor_or_duplicate_refused(self):
        rows=[(130,I("invoke-static",OWNER+"->installNodeRuntimeLocked()V"))]
        with self.assertRaises(Denied):
            exact_original_call(rows,OWNER,"installNodeRuntimeLocked","()I")
        with self.assertRaises(Denied):
            exact_original_call(rows+rows,OWNER,"installNodeRuntimeLocked",DESC)
    def test_bounded_static_method_summary(self):
        method=Method(rows=[
            (0,I("invoke-virtual","v0, Ljava/io/File;->mkdirs()Z")),
            (6,I("return-void"))])
        rows,tries,returns,branches,categories,io,helpers=static_method_stats(method)
        self.assertEqual((len(rows),tries,len(returns),len(branches)),
                         (2,0,1,0))
        self.assertEqual(io,[(0,"FILE_METADATA","mkdirs")])
        self.assertEqual(helpers,[])

if __name__=="__main__":unittest.main(verbosity=2)
