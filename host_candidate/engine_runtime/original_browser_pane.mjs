// Exact members of the verified v138 browser-pane.zip, in the order sent by Android.
const browserPaneMembers = [
  ['package.json', 565, 'd587ff5fe6f1c2ac9279ae39108268c254c042078dea8af9ef12b07522dec749'],
  ['lib/index.js', 1402, '58f9136a6b4666195451a32aa00924e4f243fa9a245fb9cee520e4519ba6f36a'],
  ['lib/client.js', 34879, '7087b8b80e06a0496ba2065eecd71559490bcb9c6d2ed5f8502fd3b46744b0c1'],
];
const browserPaneLength = browserPaneMembers.reduce((total, [, length]) => total + length, 0);
const browserPaneRoot = ROOT + '/android-browser-pane/dsh-android-browser-pane';
const browserPanePatch = ROOT + '/owner-browser-pane.patch.yml';

function installBrowserPane(bytes) {
  if (bytes.length !== browserPaneLength) fail('E_DSH_BROWSER_CAPSULE_LENGTH');
  const folders = [ROOT + '/android-browser-pane', browserPaneRoot, browserPaneRoot + '/lib'];
  if (folders.some(name => files.has(name) || directories.has(name)) ||
      files.has(browserPanePatch) || directories.has(browserPanePatch)) fail('E_DSH_BROWSER_CAPSULE_COLLISION');
  let offset = 0;
  const pending = browserPaneMembers.map(([member, length, expected]) => {
    const name = browserPaneRoot + '/' + member;
    const contents = bytes.subarray(offset, offset + length);
    offset += length;
    if (files.has(name) || directories.has(name) || createHash('sha256').update(contents).digest('hex') !== expected) {
      fail('E_DSH_BROWSER_CAPSULE_SEAL');
    }
    return [name, contents];
  });
  for (const name of folders) directories.add(name);
  for (const [name, contents] of pending) files.set(name, contents);
  const entry = pathToFileURL(browserPaneRoot + '/lib/index.js').href;
  files.set(browserPanePatch, Buffer.from(`- insert:\n    - id: dsh-android-browser-pane\n      name: '${entry}'\n`));
}
