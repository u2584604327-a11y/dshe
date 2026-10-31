#!/usr/bin/env python3
"""Overlay P113 read-only observation in an ephemeral COPY of frozen P101.
Only the original ToolRuntime.execute wrapper used by P101 test is observed.
Never edit the frozen P101 source, original APK, Node packages or Android.
"""
import argparse
from pathlib import Path
import subprocess

def one(src,old,new):
    if src.count(old)!=1:
        raise ValueError("P113_EXACT_BASELINE_ANCHOR_COUNT_"+str(src.count(old)))
    return src.replace(old,new)

def patch(source):
    source=one(source,
      "import https from 'node:https';\n",
      "import https from 'node:https';\n"
      "import {P113OriginalToolCallObservation} from './p113_original_tool_pending_observation.mjs';\n")
    source=one(source,
      "let toolRegistration=null;\n",
      "let toolRegistration=null;\n"
      "const p113Pending=new P113OriginalToolCallObservation();\n")
    source=one(source,
      "  observedTools.execute=function(exec){\n"
      "    toolRuntimeAttempts++;\n"
      "    return originalToolExecute.call(this,exec);\n"
      "  };\n",
      "  observedTools.execute=function(exec){\n"
      "    toolRuntimeAttempts++;\n"
      "    // Advisory only: original ToolRuntime gets exactly the same exec.\n"
      "    const record=p113Pending.begin({exec,handle,store:ctx.get('sessions')});\n"
      "    try{\n"
      "      const result=originalToolExecute.call(this,exec);\n"
      "      // Return the ORIGINAL promise, never a wrapper/tool result.\n"
      "      void Promise.resolve(result).then(\n"
      "        ()=>p113Pending.end(record),()=>p113Pending.end(record));\n"
      "      return result;\n"
      "    }catch(error){p113Pending.end(record);throw error;}\n"
      "  };\n")
    source=one(source,
      "  const p101pass=committedUserEvent&&prepareCalls===2&&streamCalls===2&&\n",
      "  const p113Check=p113Pending.verify({handle,store:ctx.get('sessions'),\n"
      "    calls:committedToolCalls,results:committedToolResults,assistantEvents});\n"
      "  log('P113_ORIGINAL_TOOLRUNTIME_PENDING_TO_COMMITTED_SESSION',\n"
      "    p113Check.observed?'PASS':'FAIL');\n"
      "  log('P113_ORIGINAL_TOOLRUNTIME_PENDING_COUNT',p113Check.originalToolInvocationCount);\n"
      "  log('P113_ORIGINAL_TOOLRUNTIME_SESSION_IDENTITY',\n"
      "    p113Check.originalSessionSameObject?'PASS':'FAIL');\n"
      "  log('P113_NATIVE_TOOL_AUTHORIZATION',p113Check.nativeAuthorization?'YES':'NO');\n"
      "  log('P113_NATIVE_INDEPENDENT_PENDING_CALL_PROOF',\n"
      "    p113Check.exactOriginalPendingAtNative?'YES':'NOT_PROVEN');\n"
      "  if(!p113Check.observed)process.exitCode=2;\n"
      "  const p101pass=committedUserEvent&&prepareCalls===2&&streamCalls===2&&\n")
    return source

def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--source",type=Path,required=True)
    cli.add_argument("--destination",type=Path,required=True)
    a=cli.parse_args()
    if a.source.resolve()==a.destination.resolve():
        raise ValueError("P113_MUST_NOT_EDIT_FROZEN_P101_SOURCE")
    if not a.source.is_file() or a.destination.exists():
        raise ValueError("P113_SOURCE_OR_TARGET_GATE")
    original=a.source.read_text(encoding="utf-8")
    modified=patch(original)
    assert modified!=original
    assert modified.count("p113Pending.begin({exec,handle,store:ctx.get('sessions')})")==1
    assert modified.count("const p113Check=p113Pending.verify")==1
    assert modified.count("return result;")==1
    assert "P113_NATIVE_TOOL_AUTHORIZATION" in modified
    a.destination.parent.mkdir(parents=True,exist_ok=True)
    a.destination.write_text(modified,encoding="utf-8")
    subprocess.run(["node","--check",str(a.destination)],check=True)
    print("P113_EPHEMERAL_ORIGINAL_P101_OVERLAY_SOURCE=PASS")
    print("P113_FROZEN_ORIGINAL_P101_FILE_MODIFIED=NO")

if __name__=="__main__":main()
