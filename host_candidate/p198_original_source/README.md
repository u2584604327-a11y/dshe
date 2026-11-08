# P198 — original v138 caller provenance (read-only)

Goal: identify **direct DEX callers** of the original `EngineManager.start()`, `probeBoot()`, and `runDumpConfig()` from the real signed v138 binary. Earlier P196 validated only the callee's instruction parity, not which original class would call it. This is a source-discovery prerequisite for evaluating the real original coroutine's authorized lifetime.

The auditor requires signed v138 SHA256 `3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5` and traverses original `classes*.dex` application methods. It reports bounded direct call counts, coarse owner categories, source method hashes and bytecode PCs. It never emits original invocation operands, strings, URLs, launch command, directory, environment, Java user data, credentials or APK bytes.

Direct DEX callsites are **not runtime evidence**. Android lifecycle callbacks, coroutines, interfaces, reflection or other indirect dispatch may not show a direct callsite. A zero count means only that *this static analysis did not observe a direct invoke*. Original `EngineManager$start$2.invokeSuspend` existence is required, but no original coroutine is actually invoked. No Node is started, no original state flow is mutated, no user phone is touched and no production P47 permission changes.

Run the 14 synthetic tests without APK: `python3 -B host_candidate/p198_original_source/test_entry_callers.py`.

For a SHA-pinned signed baseline obtained through the existing disposable P43 builder, run:
`python3 -B host_candidate/p198_original_source/audit_entry_callers.py signed-v138.apk --report transient-redacted.json`.

P197 existing original singleton and host Android UID/PID epoch → P68 framework Message.sendingUid → P184 receipt → P75 fixed `/system/bin/id -u` real Android35 evidence is already PASS, but not an original Kotlin coroutine identity. No static call graph can replace that missing proof. Future on-device passive source observation must not invoke original Node or force `EngineManager.start()`.

See `BROWSER_PRIVACY_QA.md` for a future manually initiated, privacy-conscious browser diagnostics reference list. External fingerprinting services are **not called by CI**. Preserve original DSHAPP MIT credits and nonendorsement notices. Formal v139 remains `STRUCTURAL_BLOCKED`.

## P198 caller entry-type refinement (2026-11-08)

The signed-v138 caller scan already proved four direct original EngineManager.start callsites, but a direct callsite does not tell us whether a user clicked anything. The read-only auditor now groups each caller into fixed method-name buckets: lifecycle method, named UI callback, coroutine continuation, ambiguous Kotlin lambda, constructor, or other. It also produces an owner-kind matrix using preexisting coarse owner categories. Original method names, DEX text, arguments, cookies, URLs and invocation register operands never enter the report/log. Twenty negative/synthetic tests check category distinctions and secret non-disclosure.

A named onClick callsite is **NOT** proof that the real view was clicked, that the View is exported or even reachable, or that the original coroutine naturally runs. The genuine-user-action attestation remains false; this stage never instruments/calls original EngineManager or executes Node. Inspect the actual CI category counts before selecting the next narrow Android35 real UI interaction; no generic tap/guess or privileged shell command may substitute for verified original UI origin.
