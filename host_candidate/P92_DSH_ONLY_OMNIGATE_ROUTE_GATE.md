# P92 DSH-only → OmniGate 8787 → unchanged original Native API

2026-10-30 user chose a single authoritative send path **from DSH only**, while retaining OmniGate as the provider API bridge. Direct user interaction in the OmniGate/underlying web UI is not a requirement for handoff continuity. This narrows the scope; it does not disable the user's OmniGate UI or modify its browser sessions.

## Source facts and invariants
- Latest phone logs show `气泡注入结果: {"len":0,"sendDisabled":true}` yet `气泡发送结果: "SENT"`, including at 21:26:54. The existing P90 receipt gate rejects that false positive. The logs do NOT contain upstream `/v1/chat/completions` HTTP traces and cannot establish which layer the request stopped at.
- OmniGate `SidecarProxyServer` GET `/health` reports `listen:127.0.0.1:8787`, `upstreamReachable`, `verifiedNativeOwner`, and `observedRuntimeRoute` after original owner inspection. This is ONLY an advisory snapshot; POST rechecks owner and may still reject 409.
- The upstream Native API must not be replaced, blindly restarted, or targeted directly by DSH. Do not rotate ports or scrape login tokens.

## Actual new code
- `P92DshRouteGate` gates one attempted POST on verified editor content, reachability and mutually exclusive main/overlay socket-owner matches. It deliberately rejects empty disabled composer and owner mismatch; 409/503/401 are final per-attempt results, not reasons to blindly retry.
- `P92OmniGateHealthReader` uses bounded GET `http://127.0.0.1:8787/health` only on a background thread, max 32 KB JSON. No POST, no authentication data in logs, and no change to gateway listening port.
- `P90SendReceiptGate` still requires a trusted new-user-turn event correlated to the correct message, not HTTP200 or [DONE]. P92 receives such a signal only through a future verified original DSH adapter.

## Still blocked (do not mark green)
1. Source-locked original DSH MainActivity bubble editor readback and P92 adapter: **NOT_WIRED**. P91 only located both main log producer callbacks and bounded callers; not the WebView JS continuation or production request lifecycle.
2. Installed original DSH MainActivity → OmniGate 8787 real POST and 409 diagnostics: **NOT_VERIFIED**.
3. Original DSH model SSE parse → actual message store → actual UI incremental paint: **NOT_VERIFIED** (P87-P89 are independent components, Android probe blocked on emulator downloads).
4. Tool-call aggregate → original plugin dispatcher → tool_result posted back to same model turn and resumed: **NOT_VERIFIED**.
5. 19:43:01 main-thread-stall diagnostic stack file still needs privacy-approved on-device inspection before identifying cause.

No automatic re-send, no egress escalation, no original APK patch, no production merge, no key/signing material.
