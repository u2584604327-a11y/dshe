# Host-owned HTTP transport for the isolated runtime

This is working transport code, not an installed production supervisor or a
READY claim. `HttpProcessTransport` has package-private construction, accepts
an already authenticated Process and never launches one. Production P47 stays
unchanged and fail-closed. The original permissionless P51 config package and production DSH remain
unchanged. A separately identified network-component test build can package
this transport; it is not an original DSH installation or upgrade.

The host binds **only 127.0.0.1** at the original launch plan's requested port;
port 0 uses the kernel-assigned port. There is no hardcoded 3080, wildcard,
destination URL, CONNECT relay, or outbound network forwarding. A fresh secret,
session and owner epoch authenticate each direction of the Process pipe. Node
intercepts exactly one original `http.Server.listen()` with the agreed IPv4
address/port, then delivers virtual Duplex connections to the original HTTP
parser. HTTPS, other ports, other addresses, listener replay and extra listeners
reject. Host/Origin, cookies, request bodies, headers and HTTP responses pass
unchanged to the original WebServer/Connection handlers.

The production worker must verify the original executable, complete module
closure, actual child start and Binder identity/receipt **before** constructing
this transport. Its raw Process stdout becomes the protocol; the returned
Process exposes application stdin/stdout/stderr separately (including merged
stderr). Bootstrap resource delivery must complete before the HTTP preface;
this does not quietly reinterpret the existing EOF-terminated config stream.
The production launch lease, resource/config broker and full main profile are
not installed by this implementation. They must not be replaced by a host
ProcessBuilder fallback. No public Binder service or factory was added here.

## Protocol and bounds

The trusted pipe begins with 88 bytes: `DSHHTTP1`, 32 random key bytes, 32 session
bytes, positive 64-bit owner epoch, requested port and bound port. All integers
are big-endian. Frames contain `DHF1`, type, positive 64-bit per-direction
sequence, 32-bit connection id, 32-bit payload length, HMAC-SHA256 and payload.
The MAC includes direction, session, epoch, complete header and payload. A frame
is at most 16 KiB; sequence replay, a different direction/epoch, unallocated ids,
excess length, malformed terminal frames and credits for unsent bytes revoke
and cancel the transport. Connection ids are never reused in a generation;
late frames for an already closed id are discarded, never attached to a new
connection.

There are at most 16 TCP connections. Each direction has a 64 KiB credit window
and the Node Readable permits at most one additional 16 KiB prefetch. Response
queues are bounded; their credits return only after a real socket write. Slow
clients have independent writer threads and cannot block the frame reader.
Blocked socket writes have a 60-second deadline; SSE idle connections retain
the original HTTP server's own timers instead of an invented global idle
expiry. Protocol queues and application log buffers are bounded too. Stdin EOF
has its own frame and does not close the resource/control pipe. Authenticated
child exit, transport loss, force cancellation and graceful SIGTERM stop the
host listener and invalidate the connection generation. Normal exit drains
framed and native stderr; unframed stdout is a protocol error. Application log stream closure signals EPIPE to that Node stream while the
HTTP/control pipe stays alive. Unsupported direct, unframed stdout writes reject;
complete main-profile descriptor usage still requires its own audit.

## Browser cookies and restart

The original Connection stores `client-connection/browser-session` in the
persistent credential provider. Independent real-service tests reproduce its
cookie remaining valid when a fresh process reuses the same host/port/home.
That conflicts with the requested invalidation of old tokens/sessions.

`browser_session_scope.mjs` gives **only that versioned signing record** an
in-memory process-generation scope before the original Connection activates.
The original Connection still generates the secret, signs/checks cookies and
exchanges its actual launch token. Other credential records stay with the
original provider. The existing credential file is not changed, erased or
exported. The scoped key survives Connection reloads in the same generation,
but not a new runtime. This is not B3/B4 or a general resource/credential grant;
production owner cancellation must also revoke its Binder/file capabilities.

## Reproducible evidence

JDK 17, Python 3.11+ and the exact original Node 26.4.0:

```
python host_candidate/engine_runtime/verify_original_http.py \
  --apk /path/to/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk --node /path/to/node
```

The runner seals the original APK SHA and full 30,411-member / 262,498,938-byte
module closure (9 native addons, not loaded by these services). It extracts only
to a temporary directory. The Node child has filesystem access only to the
original resources, test sources and fresh test home; it has **no network
permission**. A native bind without this adapter must fail with
`ERR_ACCESS_DENIED`. The Java host owns real TCP sockets and real OS pipes.

The fixture loads the unchanged original Cordis, WebServer, local credential
provider, Connection and frontend-static modules. It validates the real token
exchange, Cookie flags, rejection without authentication, hostile Host,
byte-identical rendered frontend and its actual JS asset, a 2 MiB streaming
round trip, SSE, keep-alive reauthentication, stdin/EOF, stderr, slow-client
backpressure/cancel and same-port graceful restart. Stream routes are explicit
test fixtures behind the original Connection admission; they are not claimed
as model/chat functionality. The before/after cookie test and existing
credential-file byte comparison remain required. Both protocol directions
also reject malformed frames and invented credits. A child failure before HTTP listen preserves its real
exit code and stderr instead of being misclassified as a supervisor kill.

These are host integration results. Android Binder ownership and ARM64 original
Node HTTP execution still need independent validation. The full DSH main
profile, WebView, model stream, durable account resources, outbound model
network access, B3/B4 and formal APK remain unaccepted.

## Original Android native supplement

The original `EngineManager.ensureNativeAddon()` installs
`assets/node-addon-android-arm64.zip` **outside** `engine.bin`. A streamed
engine.bin tree is therefore not the complete main-profile runtime closure.
`original_native_bundle.py` now stages the actual four-file original supplement
using the original APK SHA, archive SHA, individual lengths/hashes, regular-file
types, package/prebuild versions and a bounded ELF64 dependency/layout parser.
It copies the native bytes under one fixed APK-library alias and stages the
three unchanged JS/JSON resources with a versioned manifest. It checks the
exact original libc++ dependency already supplied by P49. Existing output
directories, links and files cannot be overwritten. No code is executed,
loaded or registered with P47 by this staging operation.

```
python host_candidate/engine_runtime/original_native_bundle.py ORIGINAL.apk \
  NEW_EMPTY_OUTPUT --device-page-size 4096
```

The supplement is version 0.1.7 (the tree's loader wrapper is 0.1.9); do not
silently replace either with a downloaded package. The actual ARM64 binding
API remains to be tested. Its original ELF has 4 KiB PT_LOAD alignment; a
16 KiB page-size request is deliberately rejected **before** any output is
created. ZIP alignment does not repair this ELF incompatibility. A device's
actual page size must be measured, not inferred from its Android API level.
The library mapping, authenticated supplemental-resource delivery and runtime
dlopen permission remain unconnected; the HTTP component APK does not load
this addon or claim a complete main-profile closure.

A local full-main probe using the sealed namespace now passes the installation
lookup that blocked the native filesystem probe, then exits 1 during original
host preparation because that host run lacks the Android native supplement.
HTTP does not listen. This is neither an ARM64 binding failure nor evidence
that the original APK lacks the binding. No original module source, filesystem
permission or native-loading permission was broadened to make it pass.

## Device evidence retained from the previous milestone

User-reported vivo ARM64 result for source
`9e8dbba3ac74910deabbff18106490d1f7091d91`, independent P51 APK SHA256
`7b7809dbd65420925db4e9b35c7edbd7ccd25fc8a12a8fb8c6b97e68d0f90109`:

```
ORIGINAL_ENGINE_RUN_DUMP_CONFIG=INVOKED
ORIGINAL_ENGINE_CONFIG_CHILD_EXIT=0
ORIGINAL_ENGINE_CONFIG_SHA256=87eec7a72bd7a19225983090ee7f595f4a0c645259598b64f8d072879fa159b5 bytes=44560
ORIGINAL_ENGINE_CONFIG_P47_AUTHENTICATED_P37_HANDOFF=PASS
ORIGINAL_ENGINE_CONFIG_ORIGINAL_READERS_WAIT_AND_RESULT=PASS
ORIGINAL_ENGINE_CONFIG_FRESH_PROFILE_ONLY=YES
ORIGINAL_ENGINE_CONFIG_SIDECAR_NOT_PRODUCTION=YES
```

This verifies the original private config method with original readers/wait and
real isolated Node in the **sidecar's fresh Context**, as reported by the user.
It does not initialize the installed DSH singleton, invoke the main start
coroutine or establish HTTP READY. Historical P151 missing-singleton statuses
remain consistent with this boundary. No original DSH data was read or changed.

A separate bounded full-main probe (not a READY test) now reaches original
`collectInstallationScopePackages()` / `packageDirFromAnchor()` and exits 1
with `ERR_ACCESS_DENIED` / `FileSystemRead` when Node's native installation
lookup probes an ancestor package.json outside the leased resource/profile
roots. No permission was broadened. The isolated production bootstrap must
route these lookups through the sealed resource namespace, then support the
required profile/file operations with owner-scoped durability. This full-main
probe is not substituted for the successful real-service component checks.

## Closed-resource service bootstrap

`build_http_bootstrap.py` composes the SHA-pinned existing P50 module core with
these HTTP/session adapters and a fixed five-service entry. The original
config bootstrap is left byte-identical. Only the composed receiver changes
its magic to `DSHMOD02` and replaces the final EOF check with a subsequent
transport preface; the original whole-tree seal still happens before any
original import. Legacy config wire and altered resource content reject.

The additional integration test delivers the complete original resource tree
through stdin, imports **193 actual original modules**, exchanges the real
Connection token and serves the original frontend. Its rendered HTML SHA must
match the independent original filesystem/resolver service run. Node gets no
native read permission for the extracted modules or a real profile and no
filesystem-write or network permission. The two permitted virtual read prefixes
(`/dsh-runtime`, `/dsh-home`) must not exist on the host; they only satisfy Node's
internal CJS permission checks for sources supplied by the sealed hooks.

This composition validates original services, not `runCli()` main-profile
startup. Its fresh credential namespace is intentionally empty. It is not an
existing-user configuration broker or durable storage implementation. Before
Android use, a verified worker must pin the composed bootstrap's exact bytes
and original ELF closure, authenticate child creation, then transfer the owned
pipes/receipt to this host adapter. That production registration remains absent.

## Android network component acceptance

`prepare_http_sidecar.py` builds only in the existing PR80 disposable CI. It
keeps the original P51 permissionless contract unchanged and uses a different
package, `com.dsh.p51.networkprobe`, with **INTERNET only on its host**. It has
only a default Android Application, its test Activity and a nonexported isolated
Service; every original DSH component is disabled. No shared UID, storage,
account, root, Shizuku or ADB permission is added. The host's fixed loopback
client uses NO_PROXY and never accepts a caller URL or launches a process.

The worker accepts one START lease from the framework sendingUid matching the
installed host UID, a fresh session/epoch, request sequence 1 and a 12-second
monotonic lease. Controls require the same UID/session/epoch and the next
request sequence. P50's fixed factory verifies isolated execution, actual ARM64
kernel, absence of worker INTERNET permission, original Node/dependency hashes
and the exact generated bootstrap before spawning. CHILD_STARTED is emitted
only after ProcessBuilder.start inside that isolated worker. Binder death,
unbind and owner destruction cancel the child.

The controller consumes the exact P68/P184 Process receipt before sending the
version-2 sealed resources. It tests real 401/303/Cookie authentication, the
independently pinned rendered frontend and 939,867-byte JS asset, hostile Host
403, authenticated child exit 0 and bounded shutdown. Auth URL and cookies never
appear in status or clipboard. This single-generation Android acceptance does
**not** claim Android SSE/restart, browser rendering, main EngineManager,
existing-user storage, chat or B3/B4. Its output retains NOT_WIRED/BLOCKED.

The authenticated FINISH frame follows log acknowledgments. The host stops
control writes and closes upstream stdin before the isolated supervisor drains
FDs and reports the actual process exit. FINISH alone is not process success.

P49's existing default/config allowlists remain strict. An explicit mutually
exclusive HTTP-test mode requires the new strict manifest and only one exact
38145-byte bootstrap, SHA256
`14d9e696e0705e5ce8ed2ca25054a9926bf1028bbb151cf4905e730c6be13315`.
Original assets/ELF/secondary DEX remain byte-preserved and the three original
EngineManager launch seams still route to the repository P47 DENY gate. A new
one-day test signer cannot upgrade com.dsh.android; no long-term key is used.
