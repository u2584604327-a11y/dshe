# OG-NET02 | Windows-proven Relay `503 device_offline` vs original phone Sidecar

Scope: diagnosis only. User supplied a real Windows Node 22+ result for `https://gw-<redacted>.claua.de/v1`: `health_http=503`, `health_category=RELAY_DEVICE_OFFLINE`, `issued_post=false`, `credentials_sent=false`. This proves a public Relay `device_offline` HTTP response, **not** its underlying cause. No external model POST/SSE or app UI reply was verified. No relay backend write/admin access in this repo was established.

## Use once, when no active model generation

Connect and authorize **one** Android device over ADB USB, keeping the original DSH and OmniGate running as configured. On Windows PowerShell with current platform-tools / Node.js 22+, run:

```powershell
adb devices
adb forward --no-rebind tcp:18787 tcp:8787
# Download the checked script from this PR branch, then:
node .\omnigate_relay_pair_probe.mjs "https://YOUR-EXISTING-GATEWAY.claua.de/v1"
adb forward --remove tcp:18787
```

The forwarding uses **PC-local diagnostic port 18787** → **unchanged phone Sidecar port 8787**. It neither rotates the phone port nor starts/stops the original service; it does not guarantee forwarding succeeds if USB is not authorized or the phone listener is absent. `--no-rebind` prevents clobbering a pre-existing host forward. Do not run if there are multiple ADB targets without selecting exactly one. Remove the diagnostic forward only if the creation succeeded. No permission bypass, root/Shizuku, settings update, app install, engine restart or API key is required.

The diagnostic independently issues one bounded, unauthenticated no-redirect `GET /health` to `127.0.0.1:18787` (ADB-forwarded device) and one `GET /health` to the user-supplied restricted `https://*.claua.de` Relay. TLS is verified normally. It never sends an assistant turn, uploads a token, reads cookies, POSTS, retries, extracts response bodies or prints a domain/IP/model name. The script only prints categorical fields; the exit code is not a production readiness gate. The two requests are near-simultaneous but are not an atomic snapshot.

## Interpretation

| Paired verdict | Next safe action |
| --- | --- |
| `SIDECAR_READY_RELAY_REGISTRATION_OR_TARGET_UNVERIFIED` | Phone Sidecar health and original Native owner are advisory-good, but Relay remains device_offline. Inspect the user's existing relay agent connection/heartbeat, device registration identity and whether this public address points to that same device. There is **no proof** yet which link is wrong. |
| `SIDECAR_ALIVE_RELAY_OFFLINE_AND_NATIVE_OWNER_UNVERIFIED` | Phone Sidecar responds but may still 409. Fix/verify original Main vs Overlay owner continuity separately; also investigate public relay connection. |
| `RELAY_OFFLINE_DEVICE_LOCAL_READINESS_UNPROVEN` | First establish USB/ADB target and phone Sidecar liveness. A missing ADB forward is not proof that the DSH app is dead. |
| `RELAY_NO_LONGER_503_REQUIRE_OGNET01_RECHECK` | The remote endpoint changed to HTTP 200. Rerun OG-NET01 once for original owner and model catalogue classification; **not** model reply proof. |
| Other / unknown | Use OG-NET01 for DNS/TLS/HTTP/owner/auth layer classification. No blind reconnect or duplicate messages. |

After verified relay registration and matching native owner, a user-initiated **single no-tool turn** must separately demonstrate actual SSE content, original SessionStore assistant commit and incremental chat UI repaint before marking OmniGate fixed. Exact original EngineManager prelaunch/isolated Process proofs remain independent; v139 remains blocked. Existing P149 HMAC and P150 observer, P47 no-fallback, P109 DENY_ALL, signed v138, original author MIT attribution and second-modification notice stay untouched.