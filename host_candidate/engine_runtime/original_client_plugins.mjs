// Signed v138 client plugin members in the fixed order sent by Android.
const browserPaneMembers = [
  ['package.json', 565, 'd587ff5fe6f1c2ac9279ae39108268c254c042078dea8af9ef12b07522dec749'],
  ['lib/index.js', 1402, '58f9136a6b4666195451a32aa00924e4f243fa9a245fb9cee520e4519ba6f36a'],
  ['lib/client.js', 34879, '7087b8b80e06a0496ba2065eecd71559490bcb9c6d2ed5f8502fd3b46744b0c1'],
];
const mobileUiMembers = [
  ['package.json', 572, 'e68485d3d889535f5bcaf19d28ae87538236e88d9b631f50f332953b0a1c09ee'],
  ['lib/index.js', 15983, '6521ed4ee17dbe3526289cbd79f1084144d99469029f7bb2275d9300b8585262'],
  ['lib/client.js', 621475, 'b8b4bca3f23b8de201b43ee2c57c73a3eaf51bad6ee09dedef58ed335e83f290'],
];
const browserPanePatch = ROOT + '/owner-browser-pane.patch.yml';
const mobileUiPatch = ROOT + '/owner-mobile-ui.patch.yml';

// Keep the original mobile client and replace its Android privilege probe.
// The original backend entry is authenticated but is never mounted or loaded.
const mobileStatusFence = Buffer.from(`
export const name = 'dsh-android-mobile';
export const inject = ['webServer'];
export function apply(ctx) {
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: '/api/dsh-android/privileged',
    handler(_req, res) {
      res.writeHead(403, {'cache-control': 'no-store'});
      res.end();
    },
  }), 'isolated mobile privilege status');
}
`);

const clientPlugins = [
  {members: browserPaneMembers, directory: 'android-browser-pane', id: 'dsh-android-browser-pane', patch: browserPanePatch},
  {members: mobileUiMembers, directory: 'android-mobile-ui', id: 'dsh-android-mobile', patch: mobileUiPatch,
   replacement: mobileStatusFence},
];

function mountClientPlugin(plugin, bytes) {
  const parent = ROOT + '/' + plugin.directory;
  const pluginRoot = parent + '/' + plugin.id;
  const folders = [parent, pluginRoot, pluginRoot + '/lib'];
  if ([...folders, plugin.patch].some(name => files.has(name) || directories.has(name))) {
    fail('E_DSH_CLIENT_PLUGIN_COLLISION');
  }
  let offset = 0;
  const pending = plugin.members.map(([member, length, expected]) => {
    const name = pluginRoot + '/' + member;
    const contents = bytes.subarray(offset, offset + length);
    offset += length;
    if (contents.length !== length || files.has(name) || directories.has(name) ||
        createHash('sha256').update(contents).digest('hex') !== expected) {
      fail('E_DSH_CLIENT_PLUGIN_SEAL');
    }
    return [name, member === 'lib/index.js' && plugin.replacement ? plugin.replacement : contents];
  });
  if (offset !== bytes.length) fail('E_DSH_CLIENT_PLUGIN_LENGTH');
  for (const name of folders) directories.add(name);
  for (const [name, contents] of pending) files.set(name, contents);
  const entry = pathToFileURL(pluginRoot + '/lib/index.js').href;
  files.set(plugin.patch, Buffer.from(`- insert:\n    - id: ${plugin.id}\n      name: '${entry}'\n`));
}
