#!/usr/bin/env python3
"""Synthetic fail-closed checks for linked original Node installer DEX audit."""
import unittest
from audit_signed_node_delegate import (
    Denied,io_class,safe_invoke_symbol,static_call_inventory,inspect_tries)

class I:
    def __init__(self,op="nop",output="",length=2):
        self.op,self.output,self.length=op,output,length
    def get_name(self):return self.op
    def get_output(self):return self.output
    def get_length(self):return self.length

class Pair:
    def __init__(self,addr):self.addr=addr
    def get_addr(self):return self.addr

class Handler:
    def __init__(self,off=102,addresses=(5,),size=1,catch_all=0):
        self.off,self.addresses,self.size,self.catch_all=off,addresses,size,catch_all
    def get_off(self):return self.off
    def get_handlers(self):return [Pair(x) for x in self.addresses]
    def get_size(self):return self.size
    def get_catch_all_addr(self):return self.catch_all

class HList:
    def __init__(self,values=None,off=100):
        self.values=[Handler()] if values is None else values
        self.off=off
    def get_list(self):return self.values
    def get_off(self):return self.off

class T:
    def __init__(self,start=1,count=3,handler_off=2):
        self.start,self.count,self.handler_off=start,count,handler_off
    def get_start_addr(self):return self.start
    def get_insn_count(self):return self.count
    def get_handler_off(self):return self.handler_off

class Code:
    def __init__(self,items=None,handlers=None):
        self.items=[T()] if items is None else items
        self.handlers=HList() if handlers is None else handlers
    def get_tries(self):return self.items
    def get_handlers(self):return self.handlers

class Method:
    def __init__(self,code):self.code=code
    def get_code(self):return self.code

ROWS=[(x,I()) for x in range(0,12,2)]

class AuditTests(unittest.TestCase):
    def test_io_classification(self):
        self.assertEqual(io_class("Ljava/io/FileInputStream;"),"INPUT_STREAM")
        self.assertEqual(io_class("Ljava/io/FileOutputStream;"),"OUTPUT_STREAM")
        self.assertEqual(io_class("Ljava/util/zip/ZipFile;"),"OTHER_IO_OWNER")
    def test_no_raw_arguments_emitted(self):
        path="/data/user/0/should-never-be-logged"
        entries=static_call_inventory([(10,I("invoke-virtual",
            "v0, v1, Ljava/io/File;->exists()Z "+path))])
        self.assertEqual(entries,[(10,"IO","FILE_METADATA","exists")])
        self.assertNotIn(path,str(entries))
    def test_raw_string_operand_not_a_callsite(self):
        self.assertEqual(static_call_inventory([(0,I("const-string",
             "v0, Ljava/io/File;->delete()Z"))]),[])
    def test_trusted_helper_method_only(self):
        entries=static_call_inventory([
            (0,I("invoke-virtual","v0, Lcom/dsh/android/termux/NodeHelper;->copyNode()V"))])
        self.assertEqual(entries,[(0,"TERMUX_HELPER","ORIGINAL_APP","copyNode")])
    def test_nonmatching_method_does_not_leak(self):
        self.assertEqual(safe_invoke_symbol("v0, arbitrary value"),None)
    def test_valid_byte_code_unit_conversion_and_handler_ref(self):
        self.assertEqual(inspect_tries(Method(Code()),ROWS),[(2,8,1,False)])
    def test_try_zero_count_rejected(self):
        with self.assertRaises(Denied):
            inspect_tries(Method(Code([T(count=0)])),ROWS)
    def test_try_bad_instruction_boundary_rejected(self):
        with self.assertRaises(Denied):
            inspect_tries(Method(Code([T(start=0,count=4)])),ROWS[:3])
    def test_missing_handler_offset_rejected(self):
        with self.assertRaises(Denied):
            inspect_tries(Method(Code([T(handler_off=3)])),ROWS)
    def test_handler_target_not_instruction_rejected(self):
        with self.assertRaises(Denied):
            inspect_tries(Method(Code(handlers=HList([Handler(addresses=(25,))]))),ROWS)
    def test_duplicate_handler_target_rejected(self):
        with self.assertRaises(Denied):
            inspect_tries(Method(Code(handlers=HList([Handler(addresses=(5,5))]))),ROWS)
    def test_catch_all_target_converted_from_code_units(self):
        h=Handler(addresses=(),size=0,catch_all=5)
        self.assertEqual(inspect_tries(Method(Code(handlers=HList([h]))),ROWS),
                         [(2,8,1,True)])
    def test_bounded_direct_call_inventory(self):
        rows=[(i*2,I("invoke-static","v0, Ljava/io/File;->exists()Z"))
              for i in range(257)]
        with self.assertRaises(Denied):static_call_inventory(rows)

if __name__=="__main__":unittest.main(verbosity=2)
