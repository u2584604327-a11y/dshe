# P102 Node-to-Android tool boundary — candidate, NOT original DSH integration

This candidate is the **next missing interface** between P101's original
ToolRuntime auto-roundtrip and P102's trusted Android35 Messenger gate.
It is a narrow Node-side one-shot envelope validator, not a second agent
or a replacement for original ToolRuntime.

Contract: a trusted original live-turn validator supplies the actual
SessionStore session ID and ToolRuntime call ID. A host-owned isolated-worker
transport supplies a native-minted 64-hex session through HELLO, then accepts
only one REQUEST frame with exact keys session/callId/toolName/arguments.
Only read_synthetic_fixture with canonical {"query":"fixture"} is allowed.
The terminal must match the same callId, SUCCESS, fixedResult,
outcomeUnknown=false and retrySafe=false. Late, stale, malformed, denied,
unknown, timed-out or concurrent replies fail closed and cannot be retried.
The original ToolRuntime, not this class, must append the original tool/result
and trigger the original AgentLoop's automatic continuation.

**Important missing trust boundary:** the injected transport and original
turn validator are *not* implemented by the original DSH EngineManager,
MainActivity or Android Node process in this repository. JS alone cannot
authenticate Binder Message.sendingUid, native approval, the installed app's
live SessionStore, or result durability. The Android P102 port now requires a **second, separate originalSessionId**
plus tool callId in every worker REQUEST. A trusted-host OriginalCallVerifier
must independently prove current SessionStore/ToolRuntime ownership when the
request arrives, before native UI approval dispatch, and after executor return.
A native host may never trust the worker's own asserted sessionId without that
verification. In this repo only the disposable Android emulator fixture provides
an explicitly fixed synthetic verifier; **no production original SessionStore
or EngineManager callback supplies it yet**. Source-level parity and the
emulator's fixed callback do not establish real DSH production provenance.
Source-level parity checks do not constitute a Binder end-to-end run.

Stop conditions for production: exact editable original host/Node ToolRuntime
hook absent; native provenance unavailable; original session/callId not
correlated in Android; uncertain execution outcome; unapproved action;
409 owner mismatch; Node feature mismatch; lost UI projection.
No APK, signature, deployment, live network, Bilibili or user-data changes.
