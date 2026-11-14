/**
 * Import-only export inventory for exact original SessionController peripheral
 * service packages. Never instantiates a service, opens network, model, tool,
 * file, Android, or user state. Prints safe export identifiers and inject keys.
 */
const packages=[
  '@deepseek-ai/dsh-agent-default-model',
  '@deepseek-ai/dsh-attachment',
  '@deepseek-ai/dsh-client-file-upload',
  '@deepseek-ai/dsh-fs',
  '@deepseek-ai/dsh-api-remote-access',
  '@deepseek-ai/dsh-session-query',
  '@deepseek-ai/dsh-typert-registry',
  '@deepseek-ai/dsh-workspace',
  '@deepseek-ai/dsh-commands',
  '@deepseek-ai/dsh-client-connection',
  '@deepseek-ai/dsh-storage-domain',
  '@deepseek-ai/dsh-session-persistence',
  '@deepseek-ai/dsh-api-gateway',
];
const safe=(s)=>/^[A-Za-z_$][A-Za-z0-9_$]{0,90}$/.test(s);

for(const spec of packages){
  try{
    const mod=await import(spec);
    const rows=Object.entries(mod)
      .filter(([name,value])=>safe(name)&&typeof value==='function')
      .map(([name,value])=>{
        const inject=Array.isArray(value.inject)?value.inject
          :value.inject&&typeof value.inject==='object'?Object.keys(value.inject):[];
        const src=Function.prototype.toString.call(value);
        const configFields=[...src.matchAll(/(?:config|options)\??\.([A-Za-z_$][A-Za-z0-9_$]{0,80})/g)]
          .map(x=>x[1]).filter(safe);
        const safeLiterals=[...src.matchAll(/['"]([A-Za-z_$][A-Za-z0-9_$-]{0,48})['"]/g)]
          .map(x=>x[1]).filter(x=>safe(x.replace(/-/g,'_')));
        return {
          name,
          arity:value.length,
          inject:inject.filter(x=>typeof x==='string'&&safe(x)).slice(0,40),
          staticKeys:Object.getOwnPropertyNames(value).filter(safe).slice(0,30),
          configFields:[...new Set(configFields)].slice(0,30),
          safeLiterals:[...new Set(safeLiterals)].slice(0,35),
          prototypeMethods:Object.getOwnPropertyNames(value.prototype||{})
            .filter(x=>x!=='constructor'&&safe(x)
              &&typeof Object.getOwnPropertyDescriptor(value.prototype,x)?.value==='function')
            .slice(0,30)
        };
      })
      .slice(0,50);
    process.stdout.write('P99_SESSION_SERVICE_EXPORT='+JSON.stringify({package:spec,rows})+'\n');
  }catch(e){
    const reason=String(e?.message||'').replace(/\/[A-Za-z0-9._/-]+/g,'<PATH>')
      .replace(/(?:Bearer |sk-)[A-Za-z0-9._-]{8,}/g,'<REDACTED>').slice(0,160);
    process.stdout.write('P99_SESSION_SERVICE_EXPORT='+JSON.stringify({
      package:spec,error:String(e?.code||e?.name||'UNKNOWN'),reason
    })+'\n');
  }
}
process.stdout.write('P99_SESSION_SERVICE_EXPORT_IMPORT_ONLY=PASS\n');
