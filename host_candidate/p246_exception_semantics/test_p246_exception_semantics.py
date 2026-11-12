#!/usr/bin/env python3
"""30 source-only fail-closed original DEX exception semantics cases."""
import unittest
from p246_exception_semantics import decode,first_difference,Deny
A="Ljava/lang/RuntimeException;"
B="Ljava/lang/IllegalStateException;"
class Pair:
 def __init__(self,t=3,addr=3):self.t=t;self.addr=addr
 def get_type_idx(self):return self.t
 def get_addr(self):return self.addr
class Handler:
 def __init__(self,off=101,size=1,pairs=None,catch=None):
    self.off=off;self.size=size;self.pairs=[Pair()] if pairs is None else pairs;self.catch=catch
 def get_off(self):return self.off
 def get_size(self):return self.size
 def get_handlers(self):return self.pairs
 def get_catch_all_addr(self):return self.catch
class Table:
 def __init__(self,entries=None,base=100):self.entries=[Handler()] if entries is None else entries;self.base=base
 def get_list(self):return self.entries
 def get_size(self):return len(self.entries)
 def get_off(self):return self.base
class Try:
 def __init__(self,start=0,width=3,off=1):self.start=start;self.width=width;self.off=off
 def get_start_addr(self):return self.start
 def get_insn_count(self):return self.width
 def get_handler_off(self):return self.off
class Code:
 def __init__(self,tries=None,table=None,total=6):
    self.tries=[Try()] if tries is None else tries
    self.table=Table() if table is None else table;self.total=total
 def get_insns_size(self):return self.total
 def get_tries(self):return self.tries
 def get_tries_size(self):return len(self.tries)
 def get_handlers(self):return self.table
class Method:
 def __init__(self,code=None,pcs=None):
    self.code=Code() if code is None else code
    self.pcs=[0,2,4,6,8,10] if pcs is None else pcs
 def get_code(self):return self.code
 def get_instructions_idx(self):return [(p,object()) for p in self.pcs]
class Dex:
 def __init__(self,types=None):self.types={3:A,4:B} if types is None else types
 def get_cm_type(self,i):return self.types[i]
def make(tries=None,table=None,total=6):
    return Method(Code(tries,table,total))
def model(m=None,d=None):return decode(m or Method(),d or Dex())
class Tests(unittest.TestCase):
 def test_01_same(self):self.assertEqual(first_difference(model(),model()),"SAME")
 def test_02_pool_renumber_same(self):
    self.assertEqual(first_difference(model(),model(make(table=Table([Handler(pairs=[Pair(25,3)])])),Dex({25:A}))),"SAME")
 def test_03_offsets_relocated_same(self):
    h=Table([Handler(off=500)],base=498)
    self.assertEqual(first_difference(model(),model(make(tries=[Try(off=2)],table=h))),"SAME")
 def test_04_try_count(self):
    a=model();self.assertEqual(first_difference(a,(a[0],())),"TRY_COUNT")
 def test_05_try_span(self):
    self.assertEqual(first_difference(model(),model(make(tries=[Try(start=1,width=2)]))),"TRY_SPAN")
 def test_06_code_size(self):
    a=model();self.assertEqual(first_difference(a,(7,a[1])),"CODE_SIZE")
 def test_07_descriptor(self):
    self.assertEqual(first_difference(model(),model(make(table=Table([Handler(pairs=[Pair(4,3)])])))),"TYPE_DESCRIPTOR")
 def test_08_target(self):
    self.assertEqual(first_difference(model(),model(make(table=Table([Handler(pairs=[Pair(3,4)])])))),"TYPED_TARGET")
 def test_09_catchall_presence(self):
    self.assertEqual(first_difference(model(),model(make(table=Table([Handler(size=-1,catch=4)])))),"CATCHALL_PRESENCE")
 def test_10_catchall_target(self):
    a=model(make(table=Table([Handler(size=-1,catch=4)])))
    b=model(make(table=Table([Handler(size=-1,catch=5)])))
    self.assertEqual(first_difference(a,b),"CATCHALL_TARGET")
 def test_11_handler_order(self):
    a=model(make(table=Table([Handler(size=2,pairs=[Pair(3,3),Pair(4,4)])])))
    b=model(make(table=Table([Handler(size=2,pairs=[Pair(4,4),Pair(3,3)])])))
    self.assertEqual(first_difference(a,b),"HANDLER_ORDER")
 def test_12_typed_count(self):
    self.assertEqual(first_difference(model(),model(make(table=Table([Handler(size=2,pairs=[Pair(3,3),Pair(4,4)])])))),"TYPED_COUNT")
 def test_13_missing_off(self):
    with self.assertRaises(Deny):model(make(tries=[Try(off=9)]))
 def test_14_duplicate_handler(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(),Handler()])))
 def test_15_misaligned_target(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(pairs=[Pair(3,7)])])))
 def test_16_bad_type(self):
    with self.assertRaises(Deny):model(d=Dex({3:"int"}))
 def test_17_invalid_span(self):
    with self.assertRaises(Deny):model(make(tries=[Try(start=2,width=8)]))
 def test_18_overlap(self):
    with self.assertRaises(Deny):model(make(tries=[Try(start=0,width=3),Try(start=2,width=2)]))
 def test_19_empty_handler(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(size=0,pairs=[],catch=None)])))
 def test_20_bad_handler_count(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(size=2,pairs=[Pair()])])))
 def test_21_bad_boundary(self):
    with self.assertRaises(Deny):model(Method(pcs=[0,2,3,6,8,10]))
 def test_22_missing_zero(self):
    with self.assertRaises(Deny):model(Method(pcs=[2,4,6,8,10]))
 def test_23_bad_size(self):
    with self.assertRaises(Deny):model(make(total=0))
 def test_24_negative_offset(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(off=99)])))
 def test_25_zero_try_empty_table(self):
    self.assertEqual(model(make(tries=[],table=Table([]))),(6,()))
 def test_26_zero_try_nonempty_table(self):
    with self.assertRaises(Deny):model(make(tries=[]))
 def test_27_negative_type_index(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(pairs=[Pair(-1,3)])])))
 def test_28_bad_catchall(self):
    with self.assertRaises(Deny):model(make(table=Table([Handler(size=-1,catch=999)])))
 def test_29_bad_comparator_input(self):
    with self.assertRaises(Deny):first_difference(None,())
 def test_30_relocated_offset_same(self):
    t=Table([Handler(off=222)],base=220)
    self.assertEqual(first_difference(model(),model(make(tries=[Try(off=2)],table=t))),"SAME")
if __name__=="__main__":unittest.main()
