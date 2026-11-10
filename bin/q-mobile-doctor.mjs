#!/usr/bin/env node
/**
 * Completely local, read-only Android/DSH compatibility probe.
 * Never prints AppSecret, tokens, the contents of credential files or ID.
 * It does not contact Tencent, log into QQ or modify any DSH configuration.
 */
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
let official;
try { official = require('@tencent-connect/dsh-qqbot/package.json'); }
catch {
  console.error('Q_MOBILE=OFFICIAL_CORE_MISSING');
  process.exitCode = 2;
}
if (official) {
  const compatible = official.name === '@tencent-connect/dsh-qqbot' &&
    official.version === '0.5.5';
  const isAndroid = process.platform === 'android' ||
    Boolean(process.env.ANDROID_ROOT || process.env.ANDROID_DATA);
  console.log('Q_MOBILE=UNOFFICIAL_ADAPTER');
  console.log('OFFICIAL_CORE=' + (compatible ? 'VERIFIED_VERSION_0.5.5' : 'UNEXPECTED_VERSION'));
  console.log('NODE=' + process.versions.node);
  console.log('ANDROID_RUNTIME_HINT=' + (isAndroid ? 'YES' : 'NO_OR_UNDETERMINED'));
  console.log('APPID_CONFIGURED=' + (Boolean(process.env.QQBOT_APPID) ? 'YES' : 'NO_OR_PROFILE'));
  console.log('SECRET_CONFIGURED=' + (Boolean(process.env.QQBOT_SECRET) ? 'YES' : 'NO_OR_PROFILE'));
  console.log('QQ_CONNECTION=NOT_TESTED');
  console.log('DSH_AGENT_SERVICE=NOT_TESTED');
  console.log('PHONE_QR_BINDING=NOT_TESTED');
  if (!compatible) process.exitCode = 3;
}
