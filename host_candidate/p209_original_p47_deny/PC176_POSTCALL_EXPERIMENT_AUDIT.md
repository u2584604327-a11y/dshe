# P209 PC176 post-call proof — controlled rollback, 2026-11-07

## Verified facts (not production proof)

Original signed v138 SHA256 is pinned to
`3ca56655d79afc57431636e340823e7071bc830615ca615c485b0b9a30b6e3e5`.
Actual signed-original PC26 `if-eqz` goes to PC176; original PC176 is
`invoke-static/range kotlin.ResultKt.throwOnFailure`, immediately followed
by PC182 `iget-object`, without a `move-result`. The original coroutine
contains FOUR `throwOnFailure` callsites. Selecting an arbitrary text
match is unsafe. P209's previous Android35 CI saw the PC176 target marker,
but not PC3912/P40/P47: it cannot prove a normal return or an exception.

## Falsifiable test-only experiment and exact stopping reason

CI-only source commits `d614e53b` -> `baf6541b` tried a distinct
post-PC176 zero-argument category marker. No original signed APK or real
account/browser files were modified. 39 Python negative/structural unit
tests passed. A bounded first-executable-opcode selector following the
original PC26 taken target correctly avoided the other three identical
ResultKt callsites. The temporary APK built successfully, but strict
signed-original vs derived DEX instruction parity rejected the extra
marker with:

`P209_PRE_PC3912_DENY_BRANCH_OPCODE_OR_WIDTH_CHANGED_INDEX_46`

Evidence: GitHub Actions run
https://github.com/u2584604327-a11y/dshe/actions/runs/42325065638

This is a **real release-blocking invariant**. The temporary after-call
marker was NOT executed on Android; its absence is not evidence of an
exception. No branch widening, register change, condition inversion, or
new ProcessBuilder fallback was approved. The experiment was reverted
from the branch tip, restoring the exact prior P209 sources and workflow
from `4abe7c196900614b95919f4282702aa705b8211b`.

## Next bounded task

Before any further post-return instrumentation, identify whether
a separate disposable test variant can replace one existing marker
without adding a DEX branch-width change, and validate EVERY original
conditional/goto target and opcode. If it cannot, leave PC176 normal
return = NOT_ATTESTED. Do not erase original trace guard checks or
change original ResultKt exception handling.

P192 isolated-UID loopback TCP remains fail-closed. B1/B2, B3, and the
B4 strictly attested Android35 OS-user/errno probes are independent.
Do not merge PR #80, publish v139, install test APKs on the owner's
phone, migrate accounts, or claim AVF/pVM.

## Reused-marker normal-return variant (new test-only experiment, not pre-approved PASS)

A prior **additive** marker after PC176 widened a branch and was correctly
rejected. This narrower experiment **moves** the existing PC176 taken-edge
witness to the instruction slot immediately after signed-v138 PC176
`invoke-static/range kotlin.ResultKt.throwOnFailure`, before original PC182
`iget-object`. The total number of disposable start$2 witness invokes stays
five, not six. The first-guard marker and PC26->PC30 fallthrough marker remain.

The signed-source verifier requires exact PC26 if-eqz successors (PC30, PC176),
exact original PC176 throwOnFailure / PC182 iget adjacency, original
instructions/operands and **every** conditional/goto opcode, width and
destination mapping. A branch to original PC176 must still land on the
original throwOnFailure, not the moved marker. If the assembler widens one
branch or redirects a target, CI FAILS CLOSED. Original DSH v138, P47
typed-deny source and network restrictions remain unchanged.

This variant deliberately relinquishes a *direct before-call PC176 event*
in favor of a *post-return PC176 event*. If the host PID logs
`P209_PC176_POST_THROWONFAILURE=OBSERVED`, the pinned PC26 branch
shape and exact relocated jump targets show the coroutine reached the
normal-return edge of the original call during this disposable run.
If absent, the result is `NOT_ATTESTED` -- it **does not** prove an
exception, UID mismatch, or direct cause. This is not real P47 start,
child process creation, or production BrowserBridge integration. Current
P209 release gate remains blocked unless the genuine same-run original
P47 final DENY evidence is also obtained.

## PC202 non-null successor variant (disposable P209 CI only)

After a previous real Android35 test witnessed the original PC176
`ResultKt.throwOnFailure` normal-return edge in the host process, the
**existing** fixed PC30 fallthrough witness was moved to just after the
signed-original PC202 `if-eqz` and just before PC206
`Process.isAlive()`. The PC176 post-return marker is retained. The
disposable `EngineManager$start$2` still contains exactly five witnesses,
not six. Original signed v138 and live production code remain untouched.

A process-ID-matched `P209_PC202_PROCESS_NONNULL_FALLTHROUGH=OBSERVED`
would prove only that the coroutine executed PC202's non-null successor
and approached the original `isAlive()` call, **not** that the process
was alive, PC214 took any branch, or P47 started. Non-observation is
`NOT_ATTESTED`; it does not prove the process field was null because
the original coroutine may exit through other edges or time out.
Since PC30 no longer has a direct witness, do NOT claim the PC26
exact-one-arm attestation in this experiment; the earlier successful
PC26 test remains historical separate evidence.

Every signed-original conditional/goto opcode, width, operand and target
must retain exact parity after the witness relocation. Invalid placement,
unrecognized process getter/isAlive shape, missing positive entry, PID
mismatch, changed production P47 typed DENY, or assembler branch widening
must fail closed. No new APK release, account data, real phone,
privileged profile operations, or network access.

## PC202 relocation rejected by signed-original DEX parity (2026-11-10)

A follow-up experiment reused the **existing** disposable PC30 marker at
the signed PC202 non-null fallthrough before PC206 `Process.isAlive()`,
while retaining the successful original PC176 post-return witness. No
new test marker, production DEX change, access permission or host Node
fallback was authorized. Strict negative unit tests increased 30 -> 33,
all 33 passed on GitHub Actions. The first trial failed *before* build
because the workflow still expected 30 tests; CI was corrected.

The next CI run built the SHA-pinned disposable derived APK, but the
mandatory signed-original instruction comparison refused the relocated
variant with the exact output:

`P209_PRE_PC3912_DENY_BRANCH_OPCODE_OR_WIDTH_CHANGED_INDEX_46`

Source: [run 42751062118, job 129614532304](https://github.com/u2584604327-a11y/dshe/actions/runs/42751062118).
**No Android35 runtime PC202 witness was obtained.** This is a genuine
fail-closed DEX branch parity rejection, NOT evidence that the original
`EngineManager.process` is null or alive, and not P47 admission.
Do NOT relax opcode/width parity, change signed-original branch widths,
or infer runtime values from an experiment that did not launch.

All six CI-only runtime/compiler/workflow files modified for this
experiment were restored byte-for-byte to their last validated
`53f0a860da5788df010f004d0fc07243360608af` blob contents,
without resetting history or changing any original DSH source.
The incident documentation is intentionally retained as evidence.
Return to the previously observed PC176 post-return path and investigate
the signed-original EngineManager process state through a separate
non-mutating method, or require an independently proven branch-preserving
instrumentation strategy before further Android runtime experiments.
P192 isolated UID TCP EACCES and all production release DENY rules
are unaffected.
