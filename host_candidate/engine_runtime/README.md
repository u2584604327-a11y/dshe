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
  --apk /path/to/DSH-vc138-P0-OFFLINE-TEST-fixed-signature.apk --node /path/to/node \
  --android-jar /path/to/existing/android-35/android.jar
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
`original_native_mapping.mjs` now maps only the verified installer-owned
`libdsh_original_require_builtin.so` to its one original virtual `.node` path.
The three original supplement JS/JSON files are embedded unchanged in the
SHA-pinned bootstrap, outside the separate unchanged engine.bin seal. The
original 0.1.9 public/custom loader resolves the original 0.1.7 supplement.
A one-use immutable dlopen guard checks exact path/module/flags; every other
native target still rejects. Original require-builtin forwards arbitrary
internal IDs: the adapter keeps its raw native exports private and exposes
only the five internal module IDs used by original app-boot. Denied IDs and
API-shape checks are part of the finite device prerequisite.

The HTTP test worker verifies the exact original native bytes, canonical
installer directory and measured 4096-byte pages before adding --allow-addons
and a read grant for that one library. It remains an isolated UID without
INTERNET or a production P47 registration. This privileged native capability
is not a JavaScript sandbox guarantee; production activation still needs
independent validation of the original loader/internal-module behavior.

The updated independent HTTP APK additionally checks real original native
binding metadata and the five Node loader interfaces. Host tests use an
explicit dlopen spy (never execute the ARM64 ELF), plus actual original
resolver/JS/JSON and mutated-metadata/path/UID/page-size/replay negatives.
They are labeled PASS_HOST/PASS_VM, not Android binding evidence. The exact
native-enabled bootstrap is 50,210 bytes, SHA256
`c78ea5b631d5716d9cf3aa324613637f5a88919f0744058b382f4b8e503f30b1`.
Its real ARM64 binding/HTTP result is pending the new device test. Original
main EngineManager, persistent profile and complete main READY remain absent.

A local full-main probe using the sealed namespace now passes the installation
lookup that blocked the native filesystem probe, then exits 1 during original
host preparation because that host run lacks the Android native supplement.
HTTP does not listen. This is neither an ARM64 binding failure nor evidence
that the original APK lacks the binding. No original module source, filesystem
permission or native-loading permission was broadened in that historical host probe.

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

The subsequent ARM64 report completed the **sender's** resource seal, then
timed out before LISTEN with the proxy still RUNNING and no reported error.
That is not receiver completion or actual child liveness. A second real defect
was present in P68's stdin pump: writes to a Process's buffered output were not
flushed. A short resource tail/preface/control frame could remain pending until
more bytes or EOF, deadlocking an interactive session. The EOF config path
could pass because closing stdin flushed its tail.

The pump now flushes after each successful write. Flush errors have the same
classification as child-input write errors, preserving late stderr and actual
exit instead of treating them as an authenticated-source failure. Genuine
source failure still cancels. The original pre-fix full P68 source is recreated
in a temporary compilation and checked against git blob
`65f69172ee029cb0566a8bf523e4d19d11382ced`; a real child reproduces the 88-byte
preface withheld until EOF. The fixed real-child test requires both that
preface and a later 53-byte control frame before EOF.

The sealed-resource integration now includes the **actual production stdin
pump**, a real OS pipe and an explicitly buffered real Node stdin. It no
longer bypasses this intermediate layer. The exact Android argv, original
authentication/frontend and actual JS bytes must pass through it. Existing
Android35 reliable-PFD tests additionally require short interactive frames
before EOF; those remain shell-UID pipe tests, not ARM64 Node evidence.

The original credentials provider validates a missing document's directory
hierarchy with `canonicalizeWatchPath()`, including `fs/promises.opendir()`.
The earlier receiver virtualized stat/realpath/readdir but left opendir native.
On the actual Android argv (root cwd, --eval, no native bootstrap-file grant),
the unchanged legacy bootstrap exits 125 with ERR_ACCESS_DENIED before listen.
The prior host file-entry test had an extra filesystem grant and did not prove
this launch shape. The device's HTTP_TRANSPORT denial alone does not prove its
private error code; the host reproduction preserves that distinction.

`readonly_directory.mjs` supplies read-only memory Dir/Dirent handles from the
already verified namespace, including sync/callback/promise reads, close and
async iteration. An ordinary file, absent directory, host path or traversal
still rejects. It opens no native directory and grants no new permission.
The SHA-pinned legacy bootstrap is still generated only as a negative control;
the Android/P49 asset allowlists accept only the fixed bootstrap. The config
bootstrap and its existing EOF protocol remain byte-identical.

The sealed HTTP integration now runs the exact Android eval argv and root cwd,
without a native script-file read grant. It reproduces the old real error and
checks the fixed real-service token exchange/frontend plus directory-handle
lifecycle and host-path negatives. This remains host evidence until the new
APK executes on the actual ARM64 device.

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
exclusive HTTP-test mode requires the new strict manifest and only the exact native-enabled bootstrap described above and the one
SHA-pinned original native supplement. The independently retained base HTTP
bootstrap remains 40,717 bytes / `680bd869d4e50ba713fb25cdfcad4b634efbaac845ece84163a759177c0bf975`;
the older 38,145-byte bootstrap is only a negative failure reproduction.
Original assets/ELF/secondary DEX remain byte-preserved and the three original
EngineManager launch seams still route to the repository P47 DENY gate. A new
one-day test signer cannot upgrade com.dsh.android; no long-term key is used.


User-reported vivo 4KiB-page ARM64 result on 2026-11-26 for the previous
stdin-flush HTTP component package: 193 original modules, real authorization,
frontend/JS byte checks, Host fence and child exit0 PASS. That report does not
independently re-hash the installed APK, test Android SSE/restart, execute the
main EngineManager coroutine, or validate this new native-enabled package.

## Full original main and the next ARM64 test

The current `prepare_http_sidecar.py` now selects `main_manifest.py` and the
fixed `engine-original-main.mjs` bootstrap. The previous HTTP composition,
manifest validator, source bytes and default/config asset modes remain
independent controls. The main mode is an additional exclusive P49 allowlist,
not a production permission flag. Its worker factory only accepts the separate
`com.dsh.p51.networkprobe` test context and authenticates a real isolated child.

The full original `runCli --profile web --port <owned port> --no-open` now uses
bounded owner snapshots, actual host file and directory force, versioned
synchronous acknowledgments, virtual watchers and the reviewed browser-session
scope. Its promise file handles implement the original JSON backend's atomic
publish path. Unsupported descriptor/stream/link operations still refuse;
this is not a complete POSIX filesystem or an existing-user storage broker.
The temporary native cache and local native build paths remain disabled.

The host control runs the actual original main, authenticates the frontend,
checks original frontend JS bytes, creates a workspace through the original
RPC, subscribes to its original WebSocket baseline, then restarts at the same
port with durable state and rejects old cookies/tokens. ARM64 dlopen in this
control is an explicit spy returning actual **host** internal loader objects.
It is never included in the generated bootstrap or accepted as Android proof.

The Android main test uses a unique `bindIsolatedService` instance per
session, real framework UID/P184 receipt, a new private TEST-owned root, and
the same HTTP/WS client. It must be physically run before claiming ARM64 main
success. The APK stays TEST ONLY, has a temporary different signer, cannot
upgrade original DSH and never reads its private files. Its status continues
`ORIGINAL_MAIN_ENGINE_START_COROUTINE=NOT_INVOKED` and `FORMAL_V139=BLOCKED`.
Android-generated overlays, all three EngineManager launch paths, production
owner authorization, model egress, browser/profile B3/B4 and original signing
remain separate release requirements. Returning from `runCli` alone is not
READY.

The user's latest reported native-prerequisite result includes the real
original binding/five internal APIs and 200 modules on the vivo 4 KiB ARM64
device. This is reported device evidence, not an independent installed-APK
hash measurement, full main run, Android restart or production attestation.
