// Host integration fixture: real original services, not the full DSH profile.
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import {writeSync} from 'node:fs';
import path from 'node:path';
const root=process.argv[2], transportSource=process.argv[3], home=process.argv[4];

try {
 const {installHttpTransport}=await import(pathToFileURL(transportSource));
 const transport=await installHttpTransport();
 const load=name=>import(pathToFileURL(root+'/node_modules/@deepseek-ai/'+name+'/lib/index.js'));
 const {Context,Service}=await load('cordis');
 const {WebServer}=await load('dsh-host-webserver');
 const {LocalCredentialProvider}=await load('dsh-credentials-local');
 const {credentialKey}=await load('dsh-credentials');
 const connection=await load('dsh-client-connection');
 const frontend=await load('dsh-host-frontend-static');
 const ctx=new Context();
 const credentials=new LocalCredentialProvider(ctx,{path:home+'/.credentials.yaml',watch:false});
 const disposers=[];
 for await (const dispose of credentials[Service.init]()) disposers.push(dispose);
 const scopeModule=await import(pathToFileURL(path.dirname(transportSource)+'/browser_session_scope.mjs'));
 const scope=process.argv[5]==='persistent-baseline'?null:scopeModule.scopeBrowserSession(credentials,credentialKey);
 const web=new WebServer(ctx,{host:'127.0.0.1',port:transport.requestedPort,compression:'none'});
 await connection.apply(ctx,{trustedHosts:[]});
 await frontend.apply(ctx,{distIndex:root+'/node_modules/@deepseek-ai/dsh-web-frontend/dist/index.html'});
 ctx.connection.fetch.register({path:'/api/transport-echo',methods:['POST'],requestBody:'streaming',
   fetch:request=>new Response(request.body,{headers:{'content-type':'application/octet-stream'}})});
 ctx.connection.fetch.register({path:'/api/transport-log',methods:['GET'],requestBody:'buffered',fetch:()=>{process.stdout.write('FIXTURE_CLOSED_STDOUT_WRITE\n');return new Response('stream-close-handled');}});
 ctx.connection.fetch.register({path:'/api/transport-sse',methods:['GET'],requestBody:'buffered',
   fetch:request=>new Response(new ReadableStream({
     start(controller){
       let n=0;const timer=setInterval(()=>{
         if(++n>6){clearInterval(timer);controller.close();}
         else controller.enqueue(new TextEncoder().encode('data: '+n+'\n\n'));
       },40);
       request.signal.addEventListener('abort',()=>{clearInterval(timer);controller.close();},{once:true});
     }
   }),{headers:{'content-type':'text/event-stream'}})});
 await web[Service.init]();
 const rendered=web.renderIndex(await readFile(root+'/node_modules/@deepseek-ai/dsh-web-frontend/dist/index.html','utf8')).replace(/<head(?:\s[^>]*)?>/i,open=>`${open}<base href="./">`);
 process.stdout.write('DSH_INDEX_SHA='+createHash('sha256').update(rendered).digest('hex')+'\n');
 process.stdout.write('DSH_WEB_URL='+ctx.connection.authenticatedUrl(web.getOrigin())+'\n');
 process.stderr.write('ORIGINAL_HTTP_FIXTURE_STDERR\n');
 writeSync(2,'ORIGINAL_HTTP_NATIVE_STDERR\n');
 const stdinChunks=[];let stdinBytes=0;
 process.stdin.on('data',chunk=>{stdinBytes+=chunk.length;if(stdinBytes>2*1024*1024)throw Error('FIXTURE_INPUT_BOUND');stdinChunks.push(chunk);});
 process.stdin.on('end',()=>process.stdout.write('DSH_STDIN_SHA='+createHash('sha256').update(Buffer.concat(stdinChunks)).digest('hex')+'\n'));
 process.on('SIGTERM',async()=>{
   await new Promise(resolve=>{web.server.close(resolve);web.server.closeAllConnections();});
   scope?.revoke();await transport.close();
 });
} catch (cause) {
 process.stderr.write('ORIGINAL_HTTP_FIXTURE=FAIL\n');process.exitCode=1;
}
