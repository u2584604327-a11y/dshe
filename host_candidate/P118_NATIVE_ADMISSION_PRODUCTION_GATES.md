# P118 — Original DSH Native Admission: proven seams and release blockers

Status: **PRODUCTION_BLOCKED**. This is an implementation contract for nonofficial secondary modifications, not a successful production adapter or a signed APK.

## Reproducible source evidence

- Repository: `u2584604327-a11y/dshe`, draft PR #80 only; original author `pht88888888/DSHAPP`, MIT. The repository's `README.md`, `NOTICE.md`, and `THIRD_PARTY_LICENSES/DSHAPP-MIT.txt` must remain intact.
- Exact modified v138 APK SHA-256: `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`. The publicly available upstream v91 Kotlin sources are **not proven equivalent** to the modified v138 APK.
- P113: the original automatic AgentLoop tool path executes one registered in-memory tool and commits original `tool/call` → `tool/result` → second model continuation, while an instance wrapper of `ctx.get('tools').execute` observes zero calls. That instance method is **not an acceptable admission hook**.
- P114/P115: the actual v138 `@deepseek-ai/dsh-agent-loop/lib/index.js` defines `executeToolCalls(ctx, turn, step, toolCalls, signal, acceptContext)`. Isolated CI-only instrumentation actually observes it once, **before** its test tool body, with the original call ID.
- P116: at that precise original helper entry, an isolated CI-only hard DENY blocks the test tool body and tool-result notification, with no network side effects. Its strict test requires one authentic helper entry, the expected original call ID, and zero executions. **The denied chat turn's graceful terminal UI behavior is not yet proven.**
- P117: the real helper's `ctx` is the exact object referenced by original `handle.loopCtx`; a signal with an `aborted` property is observed, and `acceptContext` is a function. Direct own-property `ctx.session===handle.session` was **not observed**. Do not invoke Cordis lazy getters as a side effect of diagnostics.
- P102: standalone experimental isolated worker uses Android framework `Message.sendingUid`, non-exported Binder service, strict one-use native approval and terminal/replay checks. Its experimental package is **not** the original `com.dsh.android` application.
- P108–P111: the original MIT-source Kotlin host can compile with Activity and actual EngineManager Java Process generation revocation. P109 production `OriginalCallVerifier=false`, `TrustedExecutor=false` and no original Binder or worker Service connection remain deliberate.

## Threat model and authority boundary

1. **Untrusted inputs:** model text, browser/WebView JS, plugin callbacks, files, HTTP response, serialised Node `sessionId`/`callId`, claimed PID/UID/generation, and arbitrary Node code in the same process. No such field, regardless of a matching ID, grants a native action.
2. **Android host-owned state:** real `EngineManager` Java `Process` identity/generation; native UI foreground approval; Binder framework `sendingUid`; native monotonic expiry, once-only call ledger and revoke on death/disconnect/background.
3. **Unresolved nonforgeability:** Android cannot independently inspect live JavaScript object identity or prove that a serialized request originated at the exact original `executeToolCalls` instruction rather than another script in the same Node process. Simply inserting a global JS callback, hashing a JSON request, checking the signed APK asset once, or comparing a declared call ID is **not** sufficient: same-process plugins may spoof or replay them.
4. Therefore `OriginalCallVerifier` and `TrustedExecutor` must remain **false** until the real trust separation or another independently reviewed proof is implemented. A user-confirmed native request may later support **narrow, explicitly reviewed actions**, but that is not proof of exact original SessionStore pending-call ownership and must not be represented as such.

## Required production implementation sequence

1. Map the original v138 `executeToolCalls` → `ctx` / `acceptContext` / `signal` → original tool executor → original SessionStore commit chain, including error, abort, multiple parallel calls, and turn completion. Pin its source hashes. Keep original AgentLoop logic and UI intact.
2. Specify an Android-host-owned, generation-scoped admission protocol. The native host must authenticate the **actual** isolated Binder sender, maintain per-call native state, require a fresh native UI consent for sensitive actions, and re-check authorization at *request receipt*, *approval*, and *immediately before execution*. A Node-supplied token alone is not native authority.
3. Prove that any core-origin pending-call attestation is unavailable to ordinary same-process plugins, model/browser messages, arbitrary TCP/loopback clients and stale child processes. If this isolation cannot be established, **STOP** before widening native tool privileges; retain `OriginalCallVerifier=false`.
4. Define typed, bounded, one-terminal result and rejection envelopes, original call ID binding, no duplicate execution, abort/timeout/foreground revocation, and original AgentLoop-controlled continuation. Never replace the original loop with a second implementation. Do not auto-retry unknown-outcome operations.
5. Compile original Android host integration using the exact source/binary lineage. Verify original fixed signing key can produce an **in-place** `com.dsh.android` v138→v139 upgrade **without** deleting existing chats, sessions, cookies, accounts, or assets. Distinguish source-only and emulator-only PASS from production/phone PASS.

## Mandatory acceptance / stop conditions

- Negative: forged same-ID session; altered arguments/tool name; stale generation; wrong Binder UID; expired/replayed nonce; cancellation; Activity background; host or worker death; duplicate result; malformed/oversized payload; bypassed original `executeToolCalls` hook.
- Positive: real user-approved original tool exactly once; trusted executor result delivered once; original SessionStore commit sourced to exact call; original AgentLoop resumes model; original Web UI receives streaming and final content; no hidden user-facing browser requirement, no 409 owner mismatch.
- **No signed release or automation disable** before independent Android production build and phone in-place upgrade testing, original author and third-party license inventory, diagnostic upload default DENY, WebView login retention, isolated UID, and confirmed original runtime ownership.
- Any missing proof, CI regression, unconfirmed signing identity, undocumented external side effect, original resource drift, or security bypass remains **BLOCKED**. Do not delete or uninstall the user's installed app or downloads.
