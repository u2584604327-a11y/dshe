/**
 * Q Mobile: unofficial DSH Android packaging adapter.
 * Copyright (c) 2026 initial2024. MIT, see LICENSE.
 *
 * OFFICIAL QQ CORE: @tencent-connect/dsh-qqbot@0.5.5
 * https://github.com/tencent-connect/dsh-qqbot (MIT, Tencent Connect)
 * See THIRD_PARTY_NOTICES.md for original author credit.
 *
 * IMPORTANT: No QQ transport, SDK, authentication, bot token, WebSocket,
 * session key, response, consent or access-control algorithm is implemented,
 * patched, simulated or bypassed here. Only delegates to the official plugin.
 * This is NOT an official Tencent release; it cannot guarantee account safety.
 */
import * as official from '@tencent-connect/dsh-qqbot';
import { installModelCatalog } from './model-catalog.js';

// Preserve official Cordis plugin identity: the official config persistence
// expects the stable row id "im-qqbot". Do NOT rename the internal plugin id.
export const name = official.name;
export const inject = official.inject;
export const Config = official.Config;

// Only fail early on a DSH host missing the official Agent service.
// In a valid host, all user messages and credentials are handled by official.
export function apply(ctx, config) {
  if (!ctx || !ctx.agents) {
    throw new Error('Q_MOBILE_DSH_AGENTS_NOT_AVAILABLE');
  }
  // Read-only catalog for the settings picker; optional and nonblocking.
  // QQ authentication, model routing, sessions and SDK stay official.
  installModelCatalog(ctx);
  return official.apply(ctx, config);
}
