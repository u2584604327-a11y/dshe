# P193: Android 35 isolatedProcess Binder/FD synthetic transport

Actual P192 CI proof: `P187B_BLOCKED_P187_ISOLATED_BIND_127001=BIND_EACCES`.
The isolated UID cannot be assumed able to open a TCP listener.
Do not grant INTERNET to isolated worker, remove isolatedProcess,
or permit host ProcessBuilder fallback.

P193 separately tests a disposable zero-permission Android 35 process:
- Nonexported isolatedProcess Service with Messenger Binder identity.
- Host verifies actual framework Message.sendingUid is isolated; worker
  checks the framework sendingUid equals the trusted app UID.
- A missing-FD request is rejected, then host creates a single
  ParcelFileDescriptor.createReliablePipe() and transfers its read FD.
- Isolated worker checks a fixed 14-byte synthetic payload, with bounded
  length, no browser data, Node, sockets, real phone, user accounts or pVM.
- CI only accepts one current-run boundary and one of each ordered PASS
  from a fresh x86_64 Android35 QEMU. No real APK is installed or published.

P193 success would prove only a Binder/FD primitive, not the original Node,
P192 HTTP READY, P209 coroutine, WebView account routing, work profile setup,
AVF/pVM, or v139 production readiness. The two existing failures remain hard
blockers. Never merge or release on this evidence alone.

Official platform references:
https://developer.android.com/guide/topics/manifest/service-element
https://developer.android.com/reference/android/os/ParcelFileDescriptor
