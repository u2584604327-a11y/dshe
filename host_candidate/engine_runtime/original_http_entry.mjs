// A fixed composition of real original services to validate the resource/HTTP
// boundary. It does not substitute a tiny program for the original main entry
// or claim model/chat, full EngineManager, user profiles or production READY.
let originalServiceTransport;
async function runOriginalHttpServices() {
// INSERT_REVIEWED_RESOURCE_INITIALIZATION
  const transport = await installHttpTransport();originalServiceTransport=transport;
  const load = name => import('file:///dsh-runtime/node_modules/@deepseek-ai/' + name + '/lib/index.js');
  const {Context, Service} = await load('cordis');
  const {WebServer} = await load('dsh-host-webserver');
  const {LocalCredentialProvider} = await load('dsh-credentials-local');
  const {credentialKey} = await load('dsh-credentials');
  const connection = await load('dsh-client-connection');
  const frontend = await load('dsh-host-frontend-static');
  const ctx = new Context();
  const credentials = new LocalCredentialProvider(ctx, {path: '/dsh-home/.credentials.yaml', watch: false});
  const credentialDisposers = [];
  for await (const dispose of credentials[Service.init]()) credentialDisposers.push(dispose);
  const scope = scopeBrowserSession(credentials, credentialKey);
  const web = new WebServer(ctx, {host: '127.0.0.1', port: transport.requestedPort, compression: 'none'});
  await connection.apply(ctx, {trustedHosts: []});
  await frontend.apply(ctx, {distIndex: ROOT + '/node_modules/@deepseek-ai/dsh-web-frontend/dist/index.html'});
  await web[Service.init]();
  // This is the original Connection's actual process token, confined to the
  // authenticated Process stdout. Controllers must never emit it as status.
  process.stdout.write('DSH_ORIGINAL_HTTP_URL=' + ctx.connection.authenticatedUrl(web.getOrigin()) + '\n');
  process.stdout.write('DSH_ORIGINAL_HTTP_RESOURCE_MODULES=' + loaded.size + '\n');
  process.once('SIGTERM', async () => {
    await new Promise(resolve => {web.server.close(resolve);web.server.closeAllConnections();});
    scope.revoke();
    for (const dispose of credentialDisposers.reverse()) await dispose();
    await transport.close();
  });
}
runOriginalHttpServices().catch(async cause => {
  const code = typeof cause?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(cause.code) ? cause.code : 'E_DSH_HTTP_COMPONENT';
  process.stderr.write('DSH_ORIGINAL_HTTP_ERROR=' + code + '\n');
  process.exitCode = 125;
  await originalServiceTransport?.close();
});
