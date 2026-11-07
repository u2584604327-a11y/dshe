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
