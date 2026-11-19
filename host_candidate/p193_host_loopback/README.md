# P193 — host-owned IPv4 loopback + simulated Binder frame (Java8 fixture ONLY)

2026-11-04. Repository: u2584604327-a11y/dshe, sole branch dsh/p96-original-engine-stream-owner-narrow-20261030 and Draft PR #80. This candidate does not change an original Android source, DEX, APK, user phone, credential, browser account, signature or deployment.

## Why this route

The [actual P192 same-package Android35 emulator test](https://github.com/u2584604327-a11y/dshe/actions/runs/41831819501) proved isolated-process TCP bind to 127.0.0.1 returned BIND_EACCES. Do not increase the isolated UID's permissions, disable SELinux or run the original Node engine on the host merely to obtain a PASS. The future production design must be host-owned loopback plus bounded, authenticated Binder IPC.

## What is genuinely tested

- This is a **pure Java 8, non-Android** localhost fixture. It binds a one-shot server socket only to literal IPv4 127.0.0.1 on an ephemeral port. It does not resolve hostnames, connect to the Internet, proxy arbitrary URLs or send model requests.
- The test accepts precisely GET /p193/fixture, a literal localhost Host header, a new random 256-bit bearer TEST token, Connection: close and an explicit client half-close. There is no HTTP body or request pipelining. The HTTP header limit is 1024 bytes. Unsupported methods/paths, cookies and extra headers are denied (403). A missing or invalid Binder completion produces 503, never synthetic success.
- Exactly one pending request; the simulated frame checks expected worker UID, 64-hex session and pinned asset digest, owner epoch, 256-bit nonce, sequence=1, exact fixed test bytes and response size <=32. One invalid callback permanently revokes that lease. Binder timeout is 1500 ms. All sockets are closed on terminal paths.
- The receiving method named receiveSimulatedFrameworkReply is **not a trusted UID authenticator**. Its integer UID is a fake fixture input and can be caller-supplied. Only a **future Android Handler** may read framework Message.sendingUid, verify actual worker/host UID and session, and then pass a frame to this logic. A test-only SimulatedBinderPort is not real Messenger or Binder.
- The test token getter is only for a disposable harness, not for a browser page, persistent profile, original DSH session or remotely accessible server.

Execute: bash host_candidate/p193_host_loopback/run_java8.sh. Java8-compatible source/test compiles with javac --release 8. It runs a valid in-process simulated Binder roundtrip plus denial for unauthorized token, method/path/cookie/body/header overflow, wrong UID/session/digest/epoch/nonce/seq/reply, excessive frame size, transport failure, no reply timeout, stale/replayed callback, duplicate callback and revoke.

Only the following statuses can be claimed when the exact test passes:

P193_JAVA8_OFFLINE_TEST=PASS
P193_REAL_ANDROID_FRAMEWORK_UID=NOT_TESTED
P193_ORIGINAL_ENGINE_HTTP_TOKEN_READY=NOT_WIRED

A real local HTTP response is **not** a real DSH Node startup, Android two-UID Binder authentication or HTTP token READY.

## Next required proof, not yet implemented

1. Integrate host-only IPv4 127.0.0.1 listener into a **disposable SHA-pinned original v138-derived Android test package**. Keep isolatedProcess and the original P47 host-exec deny mode. Never bind a socket in the isolated UID.
2. Implement Android Messenger with framework Message.sendingUid verification (no Bundle UID claim), real worker UID, single-use host-minted nonce, immutable digest, host/session/owner generation, exact typed commands, sequence, bounded queues and byte/time budgets. Binder death, timeout, cancellation, replay, unknown completion and stale epoch must fail closed. Test using **two actual Android UIDs**, both positive harmless fixture and negative cases. Preserve P109 native sensitive-tools DENY_ALL and GS screenshot OFF.
3. Gate actual P68/P75/P184 verified child-start and P37 process receipts separately. Then prove real ARM64 original Node, FD-delivered complete JS/module workspace, correctly scoped original EngineManager start/probe/config and token-bearing HTTP READY, with no synthetic READY.
4. Keep actual per-account browser storage (L2), complete Android VM (L5), risky hardware fingerprint imitation and website security bypass outside this P193 scope.

**Attribution / disclaimer**: [Reference projects, licensing, virtual-device truth and bilingual disclaimer](../../REFERENCE_PROJECTS_AND_VM_DISCLAIMER.md). No Shelter/gVisor/GeckoView source is copied here. This does not bypass site verification, rotate accounts to evade restrictions, certify a VM or promise v139 release. Formal v139 remains STRUCTURAL_BLOCKED.
