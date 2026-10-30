/**
 * Import the exact original first-party AgentLoop, ToolRuntime,
 * SessionController classes from the SHA-pinned DSH-v138 APK.
 * Reflection only: no constructor, plugin attach, model call or file write.
 * This is not the original Android EngineManager.
 */
const specs=[
  ['@deepseek-ai/dsh-agent-loop','AgentLoop'],
  ['@deepseek-ai/dsh-tools','ToolRuntime'],
  ['@deepseek-ai/dsh-api-session-controller','SessionController']
];
let all=true;
for(const [pkg,cls] of specs){
  try {
    const mod=await import(pkg);
    const value=mod[cls];
    if(typeof value!=='function'){
      all=false;
      process.stdout.write('P96_ORIGINAL_CLASS='+cls+' EXPORT_NOT_FUNCTION\n');
      continue;
    }
    const methods=Object.getOwnPropertyNames(value.prototype||{})
      .filter(x=>x!=='constructor' && !x.startsWith('_')).sort().slice(0,65);
    const staticMethods=Object.getOwnPropertyNames(value)
      .filter(x=>!['length','name','prototype'].includes(x)).sort().slice(0,30);
    process.stdout.write('P96_ORIGINAL_CLASS='+cls+
      ' METHODS='+JSON.stringify(methods)+
      ' STATIC='+JSON.stringify(staticMethods)+'\n');
  }catch(e) {
    all=false;
    // Never disclose original package paths or host user directories.
    process.stdout.write('P96_ORIGINAL_CLASS='+cls+
      ' IMPORT_FAILED='+(e?.code||e?.name||'UNKNOWN')+'\n');
  }
}
process.stdout.write('P96_ORIGINAL_AGENT_LOOP_TOOL_RUNTIME_MODULE_IMPORT='+
  (all?'PASS':'BLOCKED')+'\n');
process.stdout.write('P96_ORIGINAL_DSH_AGENT_TOOL_CALLBACK_WIRED=NO\n');
if(!all) process.exitCode=2;
