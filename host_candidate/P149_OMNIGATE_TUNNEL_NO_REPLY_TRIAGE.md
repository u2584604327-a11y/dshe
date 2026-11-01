# P149 | OmniGate public tunnel “no reply”: read-only fault isolation

**Status: diagnostic-only; production DSH/OmniGate tunnel NOT repaired.** Original DSHAPP MIT and secondary modification notices remain intact.

## Why local 8787 checks are insufficient

Existing `omnigate_local_preflight.mjs` tests only `127.0.0.1:8787`, not the externally configured HTTPS tunnel. Local health may be good even when the relay is offline, TLS fails or a proxy rewrites the wrong path. Past user evidence included remote `device_offline` 503, `Invalid API key`, `original_runtime_owner_mismatch` 409, and upstream 200 SSE with delayed/absent UI deltas. These must be kept separate.

## Run from your own Windows/WSL2 computer

Use Node.js 22+ and a checkout of the PR branch. Supply only your public URL; never add the API key, session token or URL query string:

```powershell
node host_candidate/p96_stream_owner/omnigate_remote_preflight.mjs "https://YOUR-EXISTING-GATEWAY.claua.de/v1"
```

This checker deliberately accepts only `https://*.claua.de` on default HTTPS port and optional `/v1`; it is not a generic open HTTP probe. It only GETs `/health` then (when the native runtime owner matches) `/v1/models`, does not send a Bearer token, send a model prompt, follow redirects, retry, log the hostname, extract user conversations or disable TLS. Non-ready exits with code 2.

## Verdict → action

| Verdict | Correct next check |
| --- | --- |
| `DNS_NO_ANSWER` / `TLS_CERT_REJECTED` / `PUBLIC_TUNNEL_TIMEOUT` | Validate tunnel DNS, HTTPS certificate, reachable relay. Do not touch active model session. |
| `PUBLIC_TUNNEL_RESET_OR_NO_REPLY` | Connection was closed without useful response: inspect relay registration, service liveness and forwarding, no blind port rotation. |
| `RELAY_DEVICE_OFFLINE` | Relay said device is disconnected. Inspect relay heartbeat and phone background service availability. |
| `REMOTE_NATIVE_OWNER_MISMATCH_NO_POST` / `REMOTE_NATIVE_OWNER_UNVERIFIED_NO_POST` | Native Main/Overlay owner guard not satisfied; preserve 409 fail-closed, investigate ownerContinuity, never auto takeover. |
| `LOCAL_NATIVE_UPSTREAM_NOT_REACHABLE` | Relay reached Sidecar but original Native API was unreachable; investigate socket owner / process generation. |
| `PUBLIC_HEALTH_AUTH_OR_POLICY_DENIED` / `PUBLIC_MODEL_AUTH_OR_POLICY_REQUIRED` | Authentication is required: confirm existing provider key in the trusted local UI only, no keys in GitHub or chat. |
| `PUBLIC_HEALTH_ROUTE_NOT_FOUND` / `PUBLIC_RELAY_REDIRECT_NOT_FOLLOWED` | Verify reverse-proxy route and that `/v1` is not duplicated. |
| `PUBLIC_GET_READY_NO_SSE_OR_ASSISTANT_REPLY_PROOF` | Only GET reachability is demonstrated. One **user-initiated, no-tool test turn** must separately prove original user-turn commit, HTTP POST native owner, SSE deltas, original assistant SessionStore commit and incremental UI paint. |

A UI message saying “no reply” can mean: (1) no HTTP response, (2) HTTP 200 but no content delta, (3) deltas received but not committed to the DSH SessionStore or (4) committed reply not rendered. No GET-only test can distinguish all four. HTTP 200 / SSE [DONE] alone is not proof that the assistant replied. Do not auto-retry any uncertain side-effectful turn.

## Public design reference and licensing

Reference reviewed: https://github.com/xingling66666/fuckds . It describes OpenAI/Anthropic-compatible responses, incremental SSE conversion, stateless prompt concatenation and a tool-call textual adapter, but it is **GPL-3.0** whereas original DSHAPP is **MIT**. The present P149 code is independently written; **no source from that GPL repository was copied**. We may independently adopt architectural *goals* (lossless SSE final frame, tool-call deduplication, actual message-store UI painting), but never copy its source into this MIT secondary modification without separate license compatibility and compliance review. Do not adopt unofficial webpage token scraping/PoW or model-formatted tool approval as a security authority.

Single writable repo `u2584604327-a11y/dshe` PR #80 only. No signed APK, phone install, user's cookies, model sessions, login, ports or private tunnel credentials modified. This diagnostic cannot repair remote Relay/cloud configuration itself.
