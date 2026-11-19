# P311 real Android35 ART target class link, no engine execution

Rebuild exact SHA-pinned original v138 derived P310 candidate and require
UNCHANGED P245 DENY + P291 cloned strict static PASS on the SAME temporary
APK. Preserve original binary manifest, third DEX, assets and libraries.
Sign only with a one-day unrelated ephemeral CI signing certificate.

In disposable Android35 x86_64 emulator, install candidate but never
launch any app Activity or EngineManager. Create a distinct Java-only ART
probe with a negative missing-class control. Drop root to shell UID 2000,
deny IPv4/IPv6 for both shell and app UID, and execute `dalvikvm
-Xverify:all` with a probe class loader. Resolve exact
`com.dsh.android.EngineManager$start$2` via `Class.forName(false)`
and reflectively find `invokeSuspend(Object):Object`; NEVER instantiate
the target, invoke that method or original Node. Require no app process.

This is only evidence of **class linking and reflective signature
resolution in a shell-user ART process**. It is NOT proof of the target
method's full bytecode verifier path, app-UID class loading, entire
EngineManager coroutine execution, native original ARM64 Node or READY,
production identity protections, or signing/release readiness.

Any missing method/class, class loading exception, network deny issue,
wrong app SHA, P245 unexpected allow, cloned strict DENY, forbidden app
process or unusual SDK: fail closed; redact all exception messages.
P245/P192/P47/B3/B4 remain unmodified DENY and v139 STRUCTURAL_BLOCKED.
