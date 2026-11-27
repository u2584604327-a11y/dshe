# P140: Real ARM64 P51 positive evidence -> original EngineManager gap

The user-reported Android ARM64 run of P139/P51 observed exact pinned original
Node running in a non-exported isolated UID, with authenticated Binder P37
Process proxy and stdout/stderr/exit.

This **closes P50's isolated synthetic Node-execution blocker**, not the original
`com.dsh.android` app's production EngineManager. P51 package is separate.

Pinned unmodified upstream `pht88888888/DSHAPP@4dddb12...` declares **three**
distinct ProcessBuilder call paths: `probeBoot()`, `runDumpConfig()`, and
`start()`. The primary path redirects stderr into stdout and requires the
engine-generated `dsh web: http://127.0.0.1:.../?token=...` line before
`State.Ready`. P50's synthetic `UID/BOOT/READY` output does not satisfy it.

P37 currently delivers stdout and stderr via separate streams and denies stdin.
P74/P75 permit only the fixed `/system/bin/id -u` fixture: they do not
authorize actual production Node argv, scripts, environment, working directory,
network, or durable secrets. P110/P111 only track process epochs and revoke
tool-port leases; they do not wire an isolated production Node broker.

Next non-bypassable step is a **same-package** authenticated worker broker
capable of delivering explicitly approved production resources/arguments
without arbitrary caller-defined paths, with a Process facade preserving
the EngineManager's stdout+stderr and lifecycle semantics. The other two
launch paths must be separately audited or kept fail-closed. Only a real
token-bearing URL after actual server boot can grant EngineManager Ready.

Tests in this folder are read-only, checkout SHA pinned and include two
negative fixtures proving that synthetic READY and arbitrary P75 argv cannot
silently become production admission. No APK, phone action, or code signing.
P109 DENY_ALL; formal v139 BLOCKED.
