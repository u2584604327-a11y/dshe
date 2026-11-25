# P311 Android 35 ART coroutine entry controls

Rebuild exact SHA-pinned original v138 derived P310 candidate and require
Require the historical P245 denial, P291 comparison, and the raw P245
comparison against both signed v138 and the derived baseline. Preserve the
baseline manifest, secondary DEX files, assets, and libraries. Use the
one-day CI certificate for the disposable installation.

Install the candidate in a disposable Android 35 x86_64 emulator. Run
`dalvikvm -Xverify:all` as shell UID 2000 with IPv4 and IPv6 denied for
both the shell and app UIDs. Keep the missing-class and class-load controls
in separate processes.

Invoke the original `EngineManager$start$2.invokeSuspend` with a null owner
in two further shell-UID processes. A Kotlin failure must propagate the
injected exception before the helper. A normal result must log the helper's
false value and reach the original owner access, where the controlled null
owner ends the invocation. Require the app process to be absent.

The result is bounded to coroutine entry and exception propagation on
shell-UID ART. Full app-UID startup, original ARM64 Node, production
isolation, and HTTP READY require separate verification.
