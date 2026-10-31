#!/usr/bin/env python3
"""P116: CI-only fail-closed exact original executeToolCalls entry demonstration.

Patch only the disposable extracted v138 AgentLoop JavaScript already instrumented
by P115, and only the ephemeral P113/P101 test driver. A hard deny at the exact
original helper entry must prevent its tool body and original result notification.
This is NOT a production bridge or a substitute for native authorization.
"""
from pathlib import Path
import argparse
import subprocess

AGENT="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"

def one(s,old,new):
    if s.count(old)!=1:raise ValueError("P116_EXACT_SOURCE_ANCHOR_"+str(s.count(old)))
    return s.replace(old,new)

def patch(runtime,test):
    helper=runtime/AGENT
    if not helper.is_file() or not test.is_file():
        raise ValueError("P116_EXPECTED_P115_DISPOSABLE_PREIMAGE")
    source=helper.read_text(encoding="utf-8")
    anchor="  // P115 isolated CI ONLY: read-only original core helper observation.\n"
    assert "__P116_ISOLATED_HARD_DENY__" not in source
    source=one(source,anchor,
      "  // P116 CI-only negative admission. The original function body is never\n"
      "  // reached when the original-host verifier is absent.\n"
      "  if (process.env.P116_ISOLATED_HARD_DENY === '1') {\n"
      "    // CI-only entry observation is never approval or execution.\n"
      "    try { globalThis.__P116_ORIGINAL_ENTRY_EVIDENCE__?.({toolCalls,signal}); }\n"
      "    catch { /* entry evidence cannot affect denial */ }\n"
      "    throw new Error('P116_UNVERIFIED_ORIGINAL_CORE_TOOL_DENIED');\n"
      "  }\n"+anchor)
    js=test.read_text(encoding="utf-8")
    js=one(js,
      "const p115Helper={calls:0,originalCallIdMatch:false,preToolBody:false,notAborted:false};\n",
      "const p115Helper={calls:0,originalCallIdMatch:false,preToolBody:false,notAborted:false};\n"
      "const p116Entry={seen:0,idMatch:false,preBody:false,notAborted:false};\n"
      "globalThis.__P116_ORIGINAL_ENTRY_EVIDENCE__=({toolCalls,signal})=>{\n"
      "  p116Entry.seen++;\n"
      "  p116Entry.idMatch=Array.isArray(toolCalls)&&toolCalls.length===1&&\n"
      "    toolCalls[0]?.id==='call_p101_0001';\n"
      "  p116Entry.preBody=toolExecutions===0;\n"
      "  p116Entry.notAborted=signal?.aborted!==true;\n"
      "};\n")
    js=one(js,
      "}finally{\n  if(handle?.session",
      "}finally{\n"
      "  if(process.env.P116_ISOLATED_HARD_DENY==='1'){\n"
      "    const stopped=p116Entry.seen===1&&p116Entry.idMatch&&\n"
      "      p116Entry.preBody&&p116Entry.notAborted&&\n"
      "      p115Helper.calls===0&&toolExecutions===0&&\n"
      "      toolNotifications===0&&networkAttempts===0;\n"
      "    log('P116_REAL_ORIGINAL_HELPER_ENTRY_SEEN_ONCE',p116Entry.seen===1?'PASS':'FAIL');\n"
      "    log('P116_REAL_ORIGINAL_CALL_ID_BEFORE_DENY',p116Entry.idMatch?'PASS':'FAIL');\n"
      "    log('P116_ORIGINAL_HELPER_DENIED_BEFORE_OBSERVER',\n"
      "      stopped?'PASS':'FAIL');\n"
      "    log('P116_NO_ORIGINAL_TOOL_BODY',toolExecutions===0?'PASS':'FAIL');\n"
      "    log('P116_NO_ORIGINAL_RESULT_NOTIFY',toolNotifications===0?'PASS':'FAIL');\n"
      "    log('P116_NO_NETWORK',networkAttempts===0?'PASS':'FAIL');\n"
      "    log('P116_ANDROID_NATIVE_PERMISSION','NEVER_GRANTED');\n"
      "    process.exitCode=stopped?0:2;\n"
      "  }\n"
      "  if(handle?.session")
    # NOTE: Deny occurs before P115 diagnostic callback, deliberately
    # enforcing a stronger entrance-boundary ordering than observation.
    helper.write_text(source,encoding="utf-8")
    test.write_text(js,encoding="utf-8")
    subprocess.run(["node","--check",str(helper)],check=True)
    subprocess.run(["node","--check",str(test)],check=True)
    print("P116_EXACT_ORIGINAL_AGENTLOOP_HELPER_HARD_DENY_PATCH=PASS_CI_ONLY")
    print("P116_DENY_PRECEDES_READONLY_OBSERVER=YES")
    print("P116_ORIGINAL_APK_NODE_AND_PHONE_UNTOUCHED=YES")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--runtime-dir",type=Path,required=True)
    ap.add_argument("--test-file",type=Path,required=True)
    args=ap.parse_args()
    patch(args.runtime_dir,args.test_file)
