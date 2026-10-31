#!/usr/bin/env python3
"""P115: only in disposable CI original-v138 Node package + test overlay.

Instruments the ACTUAL executeToolCalls() function, NOT ToolRuntime.execute().
Never writes original signed APK, deployed DSH, package plugin or PR original
source; no native permission, tool result rewrite, or network connection.
"""
import argparse
import pathlib
import re
import subprocess

AGENT="node_modules/@deepseek-ai/dsh-agent-loop/lib/index.js"

HOOK="""\n  // P115 isolated CI ONLY: read-only original core helper observation.\n  // This never supplies an approval, result, or native authorization.\n  try {\n    if (typeof globalThis.__P115_ORIGINAL_TOOL_DISPATCH_DIAGNOSTIC__ === 'function') {\n      globalThis.__P115_ORIGINAL_TOOL_DISPATCH_DIAGNOSTIC__({\n        ctx, turn, step, toolCalls, signal, acceptContext\n      });\n    }\n  } catch { /* diagnostics must never alter original AgentLoop */ }\n"""

TEST_LINES=[
"const p115Helper={calls:0,originalCallIdMatch:false,preToolBody:false,notAborted:false};",
"globalThis.__P115_ORIGINAL_TOOL_DISPATCH_DIAGNOSTIC__=({toolCalls,signal})=>{",
"  p115Helper.calls++;",
"  const first=Array.isArray(toolCalls)&&toolCalls.length===1?toolCalls[0]:null;",
"  p115Helper.originalCallIdMatch=first?.id==='call_p101_0001';",
"  p115Helper.preToolBody=toolExecutions===0;",
"  p115Helper.notAborted=signal?.aborted!==true;",
"};"
]
ASSERT_LINES=[
"  const p115Pass=p115Helper.calls===1&&p115Helper.originalCallIdMatch&&",
"    p115Helper.preToolBody&&p115Helper.notAborted&&",
"    toolExecutions===1&&toolNotifications===1&&resultLinksCall;",
"  log('P115_REAL_ORIGINAL_AGENTLOOP_EXECUTE_TOOLCALLS_ENTRY',p115Pass?'PASS':'FAIL');",
"  log('P115_REAL_ORIGINAL_HELPER_CALL_COUNT',p115Helper.calls);",
"  log('P115_ORIGINAL_CALL_ID_MATCHED_BEFORE_TOOL_BODY',",
"    p115Helper.originalCallIdMatch&&p115Helper.preToolBody?'PASS':'FAIL');",
"  log('P115_ANDROID_NATIVE_CALL_ATTESTATION','NOT_PROVEN');",
"  if(!p115Pass)process.exitCode=2;"
]

def patch(runtime: pathlib.Path, candidate: pathlib.Path):
    helper=runtime/AGENT
    if not helper.is_file() or not candidate.is_file():
        raise ValueError("P115_ORIGINAL_PACKAGE_OR_TEST_MISSING")
    body=helper.read_text(encoding="utf-8")
    assert "__P115_ORIGINAL_TOOL_DISPATCH_DIAGNOSTIC__" not in body
    expression=re.compile(
        r"\b(?:async\s+)?function\s+executeToolCalls\s*\("
        r"\s*ctx\s*,\s*turn\s*,\s*step\s*,\s*toolCalls\s*,"
        r"\s*signal\s*,\s*acceptContext\s*\)\s*\{"
    )
    hits=list(expression.finditer(body))
    if len(hits)!=1:raise ValueError("P115_REAL_HELPER_EXACT_DECLARATION_NOT_UNIQUE_"+str(len(hits)))
    match=hits[0]
    # Insert AFTER exact original function opening brace; do not replace
    # executable original statements, arguments, await expressions or returns.
    body=body[:match.end()]+HOOK+body[match.end():]
    helper.write_text(body,encoding="utf-8")
    test=candidate.read_text(encoding="utf-8")
    anchor="const p113Pending=new P113OriginalToolCallObservation();\n"
    if test.count(anchor)!=1:raise ValueError("P115_TEST_GLOBAL_ANCHOR_DRIFT")
    test=test.replace(anchor,anchor+"\n".join(TEST_LINES)+"\n")
    expected="  const p101pass=committedUserEvent&&prepareCalls===2&&streamCalls===2&&\n"
    if test.count(expected)!=1:raise ValueError("P115_TEST_ASSERTION_ANCHOR_DRIFT")
    test=test.replace(expected,"\n".join(ASSERT_LINES)+"\n"+expected)
    candidate.write_text(test,encoding="utf-8")
    subprocess.run(["node","--check",str(helper)],check=True)
    subprocess.run(["node","--check",str(candidate)],check=True)
    print("P115_ORIGINAL_V138_AGENTLOOP_HELPER_EXACT_ENTRY_PATCH=PASS_CI_ONLY")
    print("P115_ONLY_ORIGINAL_AGENT_HELPER_AND_EPHEMERAL_TEST_MODIFIED=PASS")
    print("P115_PRODUCTION_NODE_OR_ANDROID_APK_MODIFIED=NO")
    print("P115_NATIVE_APPROVAL_OR_RESULT_REWRITE=NO")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--runtime-dir",type=pathlib.Path,required=True)
    parser.add_argument("--test-file",type=pathlib.Path,required=True)
    args=parser.parse_args()
    patch(args.runtime_dir,args.test_file)
