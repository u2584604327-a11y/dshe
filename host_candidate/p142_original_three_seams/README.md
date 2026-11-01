# P142: Interpose **all three** authentic original EngineManager ProcessBuilder sites

Original upstream MIT commit: `pht88888888/DSHAPP@4dddb12fd076d052e788a16638a658b7a447b669`.

P47 had protected the primary start in the *rebuilt original main DEX* only.
Original `EngineManager.kt` retains direct ProcessBuilder.start in two
other original code paths: `probeBoot` and `runDumpConfig`. Both can start
unisolated host processes, regardless of whether the main start is denied.

This integration patch changes only the three call sites inside a **disposable
CI checkout** of upstream source to three separate typed entrypoints:
`probeOrDeny`, `configOrDeny`, `primaryOrDeny`. Each validates the original
command shape (including probe ephemeral port, config flag, primary profile)
but **always throws IOException**. No host ProcessBuilder.start, shell,
reflection or fallback may execute. The original Ready URL consumer, stdout
reader, env, overlays, bootstrap, rescue, kill/restart and process owner logic
remain byte-for-byte unmodified.

One purpose is to prevent accidentally shipping a production Broker that
interposes only the first startup call. This is a fail-closed **integration
checkpoint** rather than working full DSH runtime: the production start is
intentionally blocked and a real, same-package FD/Binder Broker is not wired.
It does not modify the user's installed original DSH, create an APK or
reproduce v139. All real device tool execution P109 DENY_ALL.

Do not claim that using this source-only patch makes DSH usable. Next work
must connect exact original immutable Node JS resource broker, signed original
APK identity, binder-isolated worker, owner epochs, stdout URL readiness and
the three independent spawn modes. Keep ephemeral source changes separate
from main and signed artifact until actual positive tests.
