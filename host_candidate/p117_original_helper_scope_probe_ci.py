#!/usr/bin/env python3
"""P117: one-shot read-only *actual* original executeToolCalls ctx/signal probe.

Source patch is restricted to disposable CI engine from exact v138 APK, and
temporary P101 driver; no exported code, secret values, native grant, model
writes or production bridge. Only boolean same-object identity metadata.
"""
from pathlib import Path
import argparse
import subprocess

ROOT="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"

def one(s,old,new):
    if s.count(old)!=1:raise ValueError("P117_EXPECTED_FROZEN_P115_ANCHOR_"+str(s.count(old)))
    return s.replace(old,new)

def patch(runtime,test):
    helper=runtime/ROOT
    if not helper.is_file() or not test.is_file():raise ValueError("P117_DISPOSABLE_SOURCE_MISSING")
    source=helper.read_text(encoding="utf-8")
    assert "__P117_ACTUAL_SCOPE_READONLY__" not in source
    anchor="  // P115 isolated CI ONLY: read-only original core helper observation.\n"
    source=one(source,anchor,
      "  // P117 CI-only scope and signal identity; no control-flow effect.\n"
      "  try {\n"
      "    globalThis.__P117_ACTUAL_SCOPE_READONLY__?.({ctx,turn,step,toolCalls,signal,acceptContext});\n"
      "  } catch { /* never alter original AgentLoop execution */ }\n"
      +anchor)
    s=test.read_text(encoding="utf-8")
    anchor2="const p115Helper={calls:0,originalCallIdMatch:false,preToolBody:false,notAborted:false};\n"
    s=one(s,anchor2,
      anchor2+
      "const p117Scope={calls:0,callMatch:false,beforeExecution:false,\n"
      "  loopCtxSame:false,sessionSame:false,signalPresent:false,\n"
      "  acceptContextType:null};\n"
      "globalThis.__P117_ACTUAL_SCOPE_READONLY__=({ctx,toolCalls,signal,acceptContext})=>{\n"
      "  p117Scope.calls++;\n"
      "  p117Scope.callMatch=Array.isArray(toolCalls)&&toolCalls.length===1&&\n"
      "    toolCalls[0]?.id==='call_p101_0001';\n"
      "  p117Scope.beforeExecution=toolExecutions===0;\n"
      "  p117Scope.loopCtxSame=ctx===handle?.loopCtx;\n"
      "  p117Scope.sessionSame=ctx?.session===handle?.session;\n"
      "  p117Scope.signalPresent=Boolean(signal&&typeof signal.aborted==='boolean');\n"
      "  p117Scope.acceptContextType=typeof acceptContext;\n"
      "};\n")
    check="  const p101pass=committedUserEvent&&prepareCalls===2&&streamCalls===2&&\n"
    s=one(s,check,
      "  const scopeObserved=p117Scope.calls===1&&p117Scope.callMatch&&\n"
      "    p117Scope.beforeExecution&&p117Scope.signalPresent;\n"
      "  log('P117_ACTUAL_ORIGINAL_HELPER_SCOPE_AND_SIGNAL',scopeObserved?'PASS':'FAIL');\n"
      "  log('P117_SCOPE_CTX_EQUALS_ORIGINAL_HANDLE_LOOPCTX',\n"
      "    p117Scope.loopCtxSame?'OBSERVED':'NOT_OBSERVED');\n"
      "  log('P117_SCOPE_CTX_SESSION_SAME_OBJECT',\n"
      "    p117Scope.sessionSame?'OBSERVED':'NOT_OBSERVED');\n"
      "  log('P117_ACCEPT_CONTEXT_TYPE',p117Scope.acceptContextType);\n"
      "  log('P117_NATIVE_INDEPENDENT_SCOPE_PROOF','NOT_PROVEN');\n"
      "  if(!scopeObserved)process.exitCode=2;\n"+
      check)
    helper.write_text(source,encoding="utf-8")
    test.write_text(s,encoding="utf-8")
    subprocess.run(["node","--check",str(helper)],check=True)
    subprocess.run(["node","--check",str(test)],check=True)
    print("P117_ACTUAL_ORIGINAL_HELPER_CTX_SIGNAL_OVERLAY=PASS_CI_ONLY")
    print("P117_original_android_production_integrity=UNMODIFIED")
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--runtime-dir",required=True,type=Path)
    p.add_argument("--test-file",required=True,type=Path)
    a=p.parse_args();patch(a.runtime_dir,a.test_file)
