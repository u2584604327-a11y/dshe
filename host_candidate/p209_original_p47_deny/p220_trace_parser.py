#!/usr/bin/env python3
"""P220: bounded allowlisted ART method-entry trace. No raw trace logging.

Sampling misses are NOT proof of no execution. Traced test startup can alter
timing; it is separate from the unchanged original P209 baseline.
"""
import argparse,re,struct,sys
from pathlib import Path
MAX_BYTES=16*1024*1024
WHITELIST={
 ("com.dsh.android.EngineManager$start$2","invokeSuspend"):"START2",
 ("com.dsh.android.termux.TermuxBootstrap","installNodeRuntime"):"NODE_INSTALL",
 ("com.dsh.android.MainActivity","bootEngine"):"BOOT_ENGINE",
 ("com.dsh.android.p40.P40ProcessBridge","start"):"P40_BRIDGE",
 ("com.dsh.android.p47.P47LaunchGate","startOrDeny"):"P47_GATE",
}
class InvalidTrace(Exception):pass
def need(ok):
 if not ok:raise InvalidTrace()
def classify(cls,meth):
 cls=cls.strip()
 if cls.startswith("L"):cls=cls[1:]
 if cls.endswith(";"):cls=cls[:-1]
 return WHITELIST.get((cls.replace("/","."),meth))
def parse(data):
 need(type(data) is bytes and 32<=len(data)<=MAX_BYTES)
 end=data.find(b"*end\n")
 need(0<end<4*1024*1024)
 text=data[:end].decode("utf-8")
 need(text.startswith("*version\n") and "*methods\n" in text)
 keys={};reading=False;rows=0
 for line in text.splitlines():
  if line=="*methods":
   need(not reading);reading=True;continue
  if line.startswith("*"):
   if reading:reading=False
   continue
  if not reading:continue
  rows+=1
  need(rows<=100000)
  cols=line.split("\t")
  need(3<=len(cols)<=12 and re.fullmatch(r"0x[0-9a-fA-F]{1,8}",cols[0]) is not None)
  mid=int(cols[0],16)
  need(mid%4==0)
  name=classify(cols[1],cols[2])
  if name is not None:
   need(mid not in keys);keys[mid]=name
 need(reading and rows>0)
 blob=data[end+5:]
 need(len(blob)>=24 and blob[:4]==b"SLOW")
 version=int.from_bytes(blob[4:6],"little")
 offset=int.from_bytes(blob[6:8],"little")
 need(version in (1,2,3) and 16<=offset<=128 and offset<=len(blob))
 size=9 if version==1 else int.from_bytes(blob[16:18],"little")
 need((9 if version==1 else 10)<=size<=32)
 records=blob[offset:]
 need(bool(records) and len(records)%size==0)
 hits={v:0 for v in set(WHITELIST.values())}
 off=1 if version==1 else 2
 for at in range(0,len(records),size):
  word=struct.unpack_from("<I",records,at+off)[0]
  if word&3:continue
  kind=keys.get(word&~3)
  if kind is not None:hits[kind]+=1
 return version,len(records)//size,hits
def main():
 p=argparse.ArgumentParser();p.add_argument("trace");a=p.parse_args()
 try:
  f=Path(a.trace)
  need(f.is_file() and not f.is_symlink() and 32<=f.stat().st_size<=MAX_BYTES)
  version,n,hits=parse(f.read_bytes())
 except Exception:
  print("P220_METHOD_TRACE=NOT_ATTESTED")
  print("P220_SAMPLING_ABSENCE_IS_NOT_NONEXECUTION=YES")
  return 2
 print("P220_METHOD_TRACE_BINARY_VALIDATION=PASS")
 print("P220_ART_TRACE_VERSION="+str(version))
 print("P220_RECORD_COUNT="+str(n))
 for kind in sorted(hits):
  print("P220_"+kind+"_ENTRY="+("OBSERVED" if hits[kind] else "NOT_ATTESTED"))
  print("P220_"+kind+"_ENTRY_COUNT="+str(hits[kind]))
 print("P220_METHOD_TRACE_ALTERS_STARTUP_TIMING=YES")
 print("P220_SAMPLING_ABSENCE_IS_NOT_NONEXECUTION=YES")
 print("P220_ORIGINAL_PC214_PC406_PC414_BRANCH=NOT_ATTESTED")
 print("P220_RAW_TRACE_OR_ARGUMENTS_EXPOSED=NO")
 print("P220_V139=STRUCTURAL_BLOCKED")
 return 0
if __name__=="__main__":sys.exit(main())
