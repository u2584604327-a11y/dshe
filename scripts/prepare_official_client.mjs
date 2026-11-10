#!/usr/bin/env node
/**
 * Q Mobile v0.1.9 nonblocking browser integration of OFFICIAL QQ Bot UI.
 *
 * Upstream @tencent-connect/dsh-qqbot@0.5.5 (MIT, © 2026 Tencent Connect).
 * Reuses official QR / AppID / secret binding UI, API routes and CSRF logic.
 * No changes to the QQ SDK, login, access rules, protocol or credentials.
 *
 * Why v0.1.1 failed: its client declared a required "slots" service at Web
 * startup. Some Android configurations initialize that service late; Cordis
 * reports the client stuck at "loading" and the ENTIRE frontend boot fails.
 * Top-level inject=[] and scoped ctx.inject() avoid blocking Web boot.
 *
 * The optional official sidebar services must be injected into their OWN
 * fiber; reading them on the outer context breaks Cordis's dependency rule.
 */
import fs from 'node:fs';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
import { PICKER_SOURCE } from './optional-model-picker.mjs';
const upstream=require('@tencent-connect/dsh-qqbot/package.json');
if(upstream.name!=='@tencent-connect/dsh-qqbot'||upstream.version!=='0.5.5')
  throw Error('OFFICIAL_CLIENT_PIN_MISMATCH');
let code=fs.readFileSync('node_modules/@tencent-connect/dsh-qqbot/lib/client.js','utf8');
function one(before,after,label){
  const count=code.split(before).length-1;
  if(count!==1)throw Error(label+'_UNEXPECTED_MATCH_COUNT_'+count);
  code=code.replace(before,after);
}
// Adapt only client module identity; keep original official service "im-qqbot"
// and API route namespace /qqbot/im-qqbot unchanged for state compatibility.
one('\tid: "@tencent-connect/dsh-qqbot",',
    '\tid: "dsh-qqbot-q-mobile",','LOADER_ID');
one('const PACKAGE_NAME = "@tencent-connect/dsh-qqbot";',
    'const PACKAGE_NAME = "dsh-qqbot-q-mobile";','DETAIL_ID');
// Top-level DSH inject dependency is intentionally EMPTY.
one('const inject = [\n\t\t\t"slots",\n\t\t\t"sidebarRight",\n\t\t\t"sidebarRightTabs"\n\t\t];',
    'const inject = [];','NONBLOCKING_INJECT');
// Only register settings if the actual slots service is available.
one('function apply(ctx) {\n\t\t\tinstallPanelStyles();',
    [
      'function apply(ctx) {',
      '  try {',
      '    if (!ctx || typeof ctx.inject !== "function") return;',
      '    ctx.inject(["slots"], (scope) => {',
      '      try {',
      '        installPanelStyles();'
    ].join('\n'),'LAZY_SETTINGS_START');
// No use of ctx.sidebarRight/ctx.sidebarRightTabs/ctx.slots on the outer fiber.
one('const tabs = ctx.sidebarRightTabs;\n\t\t\tconst right = ctx.sidebarRight;\n\t\t\tconst slots = ctx.slots;',
    'const slots = scope.slots;','NO_OUTER_SERVICE_GETTERS');
// Preserve official right sidebar binding when both services actually exist.
one('if (tabs !== void 0 && slots !== void 0) {',
    [
      'scope.inject(["sidebarRight", "sidebarRightTabs"], (sidebarScope) => {',
      '  try {',
      '    const tabs = sidebarScope.sidebarRightTabs;',
      '    const right = sidebarScope.sidebarRight;',
      '    if (tabs !== void 0 && slots !== void 0) {'
    ].join('\n'),'OPTIONAL_SIDEBAR_START');
one('\n\t\t\tconst ctxInject = ctx.inject;',
    [
      '\n  } catch(error) {',
      '    console.warn("[Q Mobile] Optional sidebar unavailable:", error?.message || error);',
      '  }',
      '});',
      'const ctxInject = scope.inject;'
    ].join('\n'),'OPTIONAL_SIDEBAR_END');
one('ctxInject.call(ctx, ["layout"], (pageCtx) => {',
    'ctxInject.call(scope, ["layout"], (pageCtx) => {','SCOPED_LAYOUT');
one('ctx.effect(() => () => {',
    'scope.effect(() => () => {','SCOPED_DISPOSE');
one('}, "im-qqbot-client.binding");\n\t\t}\n\t\t/**',
    [
      '}, "im-qqbot-client.binding");',
      '      } catch(error) {',
      '        console.warn("[Q Mobile] QQ settings deferred mount failed:", error?.message || error);',
      '      }',
      '    });',
      '  } catch(error) {',
      '    console.warn("[Q Mobile] QQ client registration skipped:", error?.message || error);',
      '  }',
      '}',
      '/**'
    ].join('\n'),'FAIL_CLOSED_BOOT_END');
// Optional settings UI remains isolated in its own React component: no hook
// is injected into the existing Tencent ConfigPanel. Failed catalog discovery
// cannot stop rendering the official config editor and QR bind panel.
one('const STYLE_ID = "im-qqbot-config-panel-styles";',
  PICKER_SOURCE + '\nconst STYLE_ID = "im-qqbot-config-panel-styles";',
  'Q_MOBILE_ISOLATED_PICKER');
one('"模型"), (0, react.createElement)(FieldRow, {',
  '"模型"), (0, react.createElement)(QMobilePicker, { form, patch }), (0, react.createElement)(FieldRow, {',
  'Q_MOBILE_PICKER_MOUNT');
code=code.replace(/\n\/\/# sourceMappingURL=client\.js\.map\s*$/,'\n');
const markers=[
  'const inject = [];',
  'ctx.inject(["slots"]',
  'scope.inject(["sidebarRight", "sidebarRightTabs"]',
  '/qqbot/im-qqbot/bind',
  '/qqbot/im-qqbot/bind/manual',
  'settings.section','plugins.detail.actions','sidebar.right.pane.tab',
  '"手动填写"', 'QMobilePicker', 'qm-safe-model-select',
  '/qqbot/q-mobile/models'
];
for(const marker of markers)
  if(!code.includes(marker))throw Error('OFFICIAL_UI_MARKER_MISSING_'+marker);
if(code.includes('@tencent-connect/dsh-qqbot'))
  throw Error('UNPATCHED_CLIENT_ID');
const copyright=[
  '/*',
  ' * Q Mobile v0.1.9: nonblocking Android DSH client integration.',
  ' * Official @tencent-connect/dsh-qqbot@0.5.5 client (MIT).',
  ' * Copyright (c) 2026 Tencent Connect.',
  ' * Unmodified QR, auth, API routes and QQ protocol.',
  ' * Third-party license: THIRD_PARTY_LICENSE_TENCENT.txt.',
  ' */',''
].join('\n');
fs.mkdirSync('lib',{recursive:true});
fs.writeFileSync('lib/client.js',copyright+code,'utf8');
const license=fs.readFileSync('node_modules/@tencent-connect/dsh-qqbot/LICENSE','utf8');
if(!license.includes('MIT License')||!license.includes('Copyright (c) 2026 Tencent Connect'))
  throw Error('UPSTREAM_MIT_LICENSE_MISMATCH');
fs.writeFileSync('THIRD_PARTY_LICENSE_TENCENT.txt',license,'utf8');
console.log('Q_MOBILE_VERSION=0.1.9');
console.log('WEB_BOOT_REQUIRED_SERVICES=NONE');
console.log('SETTINGS=DEFERRED_SCOPED_SLOTS');
console.log('SIDEBAR=OPTIONAL_SCOPED');
console.log('OFFICIAL_QQ_AUTH_SDK=UNCHANGED');
console.log('ANDROID_QR_E2E=NOT_VERIFIED');
