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
def trace_size_band(value):
 if type(value) is not int or value<0:return "INVALID"
 if value==0:return "EMPTY"
 if value<32:return "TINY"
 if value>MAX_BYTES:return "ABOVE_CAP"
 return "WITHIN_CAP"
def need(ok,stage="UNEXPECTED"):
 if not ok:raise InvalidTrace(stage)
def classify(cls,meth):
 cls=cls.strip()
 if cls.startswith("L"):cls=cls[1:]
 if cls.endswith(";"):cls=cls[:-1]
 return WHITELIST.get((cls.replace("/","."),meth))
def parse_method_id(token):
 # Explicit subset of Android VmTraceParser's Long.decode key syntax.
 # Reject unrecognized spellings rather than guessing method identity.
 if re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}",token):
  mid=int(token[2:],16)
 elif re.fullmatch(r"#[0-9a-fA-F]{1,16}",token):
  mid=int(token[1:],16)
 elif re.fullmatch(r"[0-9]{1,20}",token):
  mid=int(token,10)
 else:
  if not token: kind="EMPTY"
  elif len(token)>64:kind="OVERSIZED"
  elif re.fullmatch(r"[0-9a-fA-F]{1,16}",token):kind="BARE_HEX"
  elif token.startswith(("0x","0X","#")):kind="MALFORMED_PREFIXED_HEX"
  elif token.startswith(("+","-")):kind="SIGNED_NUMBER"
  else:kind="OTHER"
  raise InvalidTrace("METHOD_KEY_FORMAT_"+kind)
 need(mid<=0xffffffffffffffff,"METHOD_KEY_RANGE")
 need(mid%4==0,"METHOD_KEY_ALIGN")
 return mid
def parse(data):
 need(type(data) is bytes and 32<=len(data)<=MAX_BYTES,"BOUNDED_FILE")
 # ART header uses *end as delimiter. Allow CRLF, but never dump raw bytes.
 found=re.search(br"\*end\r?\n",data[:4*1024*1024])
 need(found is not None and 0<found.start()<4*1024*1024,"KEY_TERMINATOR")
 end=found.start()
 text=data[:end].decode("utf-8").replace("\r\n","\n")
 need(text.startswith("*version\n") and "*methods\n" in text,"KEY_SECTIONS")
 keys={};reading=False;rows=0
 for line in text.splitlines():
  if line=="*methods":
   need(not reading,"DUPLICATE_METHOD_SECTION");reading=True;continue
  if line.startswith("*"):
   if reading:reading=False
   continue
  if not reading:continue
  if not line.strip():continue
  rows+=1
  need(rows<=100000,"METHOD_ROW_BOUND")
  cols=line.split("\t")
  need(3<=len(cols)<=12,"METHOD_COLUMNS_UNSUPPORTED")
  mid=parse_method_id(cols[0])
  name=classify(cols[1],cols[2])
  if name is not None and mid<=0xffffffff:
   need(mid not in keys,"DUPLICATE_TARGET_METHOD_KEY");keys[mid]=name
 need(reading and rows>0,"METHOD_SECTION_EMPTY")
 blob=data[found.end():]
 need(len(blob)>=24 and blob[:4]==b"SLOW","BINARY_MAGIC_OR_EMPTY")
 version=int.from_bytes(blob[4:6],"little")
 offset=int.from_bytes(blob[6:8],"little")
 need(version in (1,2,3) and 16<=offset<=128 and offset<=len(blob),"BINARY_VERSION_OR_OFFSET")
 size=9 if version==1 else int.from_bytes(blob[16:18],"little")
 need((9 if version==1 else 10)<=size<=32,"BINARY_RECORD_SIZE")
 records=blob[offset:]
 need(bool(records) and len(records)%size==0,"BINARY_RECORD_ALIGNMENT")
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
  need(f.is_file() and not f.is_symlink(),"TRACE_LOCAL_FILE")
  size=f.stat().st_size
  print("P220_TRACE_SIZE_BAND="+trace_size_band(size))
  need(32<=size<=MAX_BYTES,"TRACE_FILE_SIZE")
  version,n,hits=parse(f.read_bytes())
 except Exception as error:
  stage=error.args[0] if isinstance(error,InvalidTrace) and error.args else "UNEXPECTED"
  allow={"TRACE_LOCAL_FILE","TRACE_FILE_SIZE","BOUNDED_FILE","KEY_TERMINATOR",
         "KEY_SECTIONS","DUPLICATE_METHOD_SECTION","METHOD_ROW_BOUND",
         "METHOD_KEY_ALIGN","METHOD_KEY_RANGE",
         "METHOD_COLUMNS_UNSUPPORTED",
         "METHOD_KEY_FORMAT_EMPTY","METHOD_KEY_FORMAT_OVERSIZED",
         "METHOD_KEY_FORMAT_BARE_HEX","METHOD_KEY_FORMAT_MALFORMED_PREFIXED_HEX",
         "METHOD_KEY_FORMAT_SIGNED_NUMBER","METHOD_KEY_FORMAT_OTHER",
         "DUPLICATE_TARGET_METHOD_KEY",
         "METHOD_SECTION_EMPTY","BINARY_MAGIC_OR_EMPTY","BINARY_VERSION_OR_OFFSET",
         "BINARY_RECORD_SIZE","BINARY_RECORD_ALIGNMENT","UNEXPECTED"}
  if stage in allow and stage.startswith("METHOD_KEY_FORMAT_"):
   print("P225_INVALID_METHOD_ID_SHAPE="+stage[len("METHOD_KEY_FORMAT_"):])
  print("P220_TRACE_FAILURE_STAGE="+(stage if stage in allow else "UNEXPECTED"))
  print("P220_METHOD_TRACE=NOT_ATTESTED")
  print("P220_SAMPLING_ABSENCE_IS_NOT_NONEXECUTION=YES")
  return 2
 print("P225_METHOD_KEY_DECIMAL_AND_HEX_SUPPORT=PASS")
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
