# P308 — One real original-derived Android35 package, P143 original FD + P193 host loopback
This is a disposable original-v138 SHA-pinned **CI-only** integration test, not a release app.
P143 and P193 have separate real-emulator positive proofs; P308 combines their exact
already-existing sources under the single authenticated P43 Host/Isolated session.
It uses P193's SHA-pinned CI-only patcher on the original P43 worker/Activity/builder,
preserves P76 original archive transfer, and starts one P43ProbeActivity with
`p193_host_ipc=true` and `p76_archive=true`. The original P43 worker accepts only
framework-verified host UID and the same session for both; P76 sends a read-only
unlinked original engine archive FD, and P193 handles fixed synthetic HTTP GET
on the ordinary host's **127.0.0.1** socket with framework-UID authenticated Binder.
The isolated UID never listens on TCP. It cannot execute Node or JS.

The runner requires a real Android 35 x86_64 QEMU emulator with no preexisting
`com.dsh.android`, a disposable signed-original-derived APK that passes
original-asset, DEX and P47/P181/P182 no-host-fallback gates, public egress deny,
one run-boundary marker, fixed P193 UID/session/replay witnesses, original P143
engine FD SHA, P77 full TAR root, P78 module read-once, P144/P145/P146/P147
source witnesses, each exactly once after the boundary. Known failures
fail closed. It emits no token, account, raw logcat, bundle path or session.
Always uninstall the disposable APK and remove only its emulator UID rules.

P308 success proves these two separately proven mechanisms can coexist
in one authenticated original-derived app test **without original Node execution**.
It is NOT original EngineManager->P37 proxy, full Node module resolution,
ARM64 Android compatibility, original HTTP token READY or BrowserBridge
profile integration. P245 original DENY, P192 isolated UID loopback BIND_EACCES
and B3/B4 production release gates remain unchanged. No actual user device,
signer, original release APK, credentials or account data is touched.
No merging, signing or formal v139 release permitted.
